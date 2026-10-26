# Dedicated Google Drive recovery drill

Execution requires the coordinating root agent's explicit release and a dedicated
account authorized privately by its owner. The recorded evidence and remaining
gates are in [ACCEPTANCE.md](ACCEPTANCE.md); this procedure alone establishes no
live-provider success. Creating these files, running pure tests, compiling, or
running the default preparation command does not contact Google, the native API,
PostgreSQL, SSH, Docker, or any storage provider. Preparation creates no runtime
checkpoint or evidence file. Do not run a live-Drive test as part of preparation.

The future proof uses an explicitly selected existing app destination and a
dedicated synthetic test account. It never chooses a Google account, creates a
Cloud project, imports another account's grant, or asks for OAuth credentials
in chat. Client details and consent stay in the app's private setup/Reconnect
flow. The harness reads current encrypted SQL credentials only after ROOTGO;
tokens never appear in command arguments, printed errors or public evidence.
The account's dedicated-test status is an explicit owner acknowledgement, not
an independently verified Google identity claim.

Run preparation with the destination UUID, once that nonsecret ID is known:

```bash
.venv/bin/python scripts/prove_drive_recovery.py \
  --dedicated-test-account --destination-id DESTINATION_UUID --phase roundtrip
```

Replace `DESTINATION_UUID` with the exact existing destination ID. A real,
canonical UUID is required even in preparation. Without `--execute`, this
prints the parked workflow and exits without opening private files or clients.
No `docs/evidence/drive.json` will exist from preparation alone.

Before a later execution, the private UI actions are:

1. In the existing app reachable on local port 8098, configure the owner's
   dedicated Google OAuth client using the private fields. Use the callback
   shown by the current app configuration; the native controller's configured
   origin is `http://127.0.0.1:8098`, and the current server callback path is
   `/api/v1/oauth/drive/callback`. The app uses a Web client, PKCE and
   `drive.file`. Keep the client and its Google project stable so the same
   historical folder remains accessible after Reconnect.
2. Authorize the exact dedicated My Drive test account through the app and
   complete its queued authorization job. Do not select a personal or
   production account. This harness does not exercise shared drives.
3. Give root only the nonsecret destination UUID and the fact that private
   authorization completed. Do not paste client secrets, access tokens,
   refresh tokens, callback codes or authorization URLs into chat.
4. Root verifies that no job/session/pending credential recovery owns this
   destination, reserves the synthetic native source, and sends ROOTGO. The
   source is the enrolled `46ac8eb9-1854-4fc6-924f-af14c6b7d0c2`, its exact
   `vr-ssh-source` container and bind data under
   `/srv/vaultrewind-fixtures/source/data`. No new attachment or database
   fixture mutation is required by this Drive drill.

Only then run the actual round trip:

```bash
.venv/bin/python scripts/prove_drive_recovery.py \
  --dedicated-test-account --destination-id DESTINATION_UUID --phase roundtrip \
  --execute --root-go ROOTGO
```

The default private checkpoint is
`.runtime/drive-proof/<destination-UUID>/checkpoint.json`; an explicit
`--run-id RUN_UUID` selects another UUID directory for an independently
reviewed attempt. Reuse the same run ID when continuing a phase. Do not create
a new run ID to bypass an ambiguous or failed restore. Checkpoints and private
manifests are owner-only. Sensitive token material retained for CAS/revocation
reconciliation is encrypted using the controller box with a bound context.
Public evidence contains safe IDs and outcomes, not folder names, credentials
or the recovered manifest's private environment.

The roundtrip phase performs these steps:

1. Guard the exact native origin, private fixture identity, selected Drive
   backend, current authorized grant, folder/scope and the absence of another
   instance/controller repository on this dedicated destination. Record the
   original disabled source policy. Preserve its schedule, runner, budgets,
   retention and required flags. Temporarily add Drive as required alongside
   the existing required local copy; preserve other original selections.
2. Force only the stored access-token expiry into the past. Preserve the
   access token, refresh token, client, folder, grant and all other fields.
   Use `SQLCredentialStore.compare_and_swap` with both generation and revision
   under its global `state_directory/session-locks` credential lock. Hold the
   controller credential-resource row lock and reject even an expired owned
   lease. Refuse **all** registered destination sessions, including orphaned
   sessions, and all pending rotations. Product recovery must reconcile those
   before another attempt; the harness never overwrites or deletes them.
3. Submit Backup now through the real API and wait for its real worker. No
   Python OAuth refresh call or connection probe runs between expiry injection
   and backup. Require both selected copies complete and source outcome
   running. Verify that rclone's changed access token/future expiry and
   `token_refreshed_at` were persisted to encrypted SQL with a newer revision,
   while the generation and grant stayed the same. A later readback/probe is
   not substituted for the backup's refresh evidence.
4. Restore the exact Drive copy into an empty private readback directory using
   the product's SQL-backed repository adapter and actual restic
   `restore --verify`. Verify its catalog-bound manifest, complete file map,
   SQLite integrity/references, standalone database and saved-image hash.
   Independently read back the same local point and compare full file-map
   hashes. Never rewrite the primary source to demonstrate a readback.
5. Record the helper's source-recovery history and source-running observation
   during cloud commit. Source resume must precede staged sealing, transfer
   and cloud work. Restore the original source policy in `finally`, including
   its disabled schedule and runner. Preserve snapshots and repositories.

The persistent credential-state directory must exactly match the worker's
`settings.provider_credential_state_dir`, or, when unset,
`settings.staging_dir.parent / "provider-credentials"`. For the current native
layout this defaults to
`/srv/vaultrewind-native-controller/provider-credentials`. The old
`cache/provider-credentials` path is not used. Pass
`--credential-state-dir /absolute/private/path` only if root has verified that
the worker explicitly uses that setting. A mismatched directory would provide
the wrong lock namespace. Do not move, seed or clean credential state to make
the drill pass.

An application restore requires a separate serialized target release, after
root's final browser work. The only supported target for this drill is the
already prepared existing synthetic VM alternate
`b05f7958-3d3b-48d6-a8f2-8eb900533149`. Root supplies its exact loopback public
origin and sends `ROOTGO_TARGET`; the script never opens a direct VM SSH or
Docker connection. Add these flags to the roundtrip command, or to a later
continuation of that same run:

```bash
  --target-id b05f7958-3d3b-48d6-a8f2-8eb900533149 \
  --target-go ROOTGO_TARGET --target-public-origin http://127.0.0.1:TARGET_PORT
```

Replace `TARGET_PORT` with root's approved port. The API plan explicitly binds
`copy_id` to the selected Drive copy and `target_id` to this alternate. The
normal replacement workflow must create a pinned complete local safety
snapshot. Require actual application startup, restored-byte verification,
activation completion and HTTP 200 from target `/alive` and `/api/config`.
Compare the original source's container start time, running state and entire
data inventory content/ownership/mode hash before and after. No primary-source
restore is accepted. Without target GO, roundtrip evidence remains a verified
storage readback and does not claim application deployment.

The current QEMU alternate publishes port `18100` inside the guest. For the
controller-side HTTP witness, open a separate pinned, loopback-only SSH forward
from the fixture host before supplying `http://127.0.0.1:18100`:

```sh
ssh -N -p 22229 -i .runtime/vm/id_ed25519 \
  -o BatchMode=yes -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile=.runtime/vm/known_hosts \
  -o ExitOnForwardFailure=yes \
  -L 127.0.0.1:18100:127.0.0.1:18100 root@127.0.0.1
```

This transport does not change target containers or DNS. Use only these
disposable fixture coordinates; it is separate from the laptop's app forward.

After the roundtrip, root coordinates one fresh **Reconnect** through the same
app private authorization flow and the same dedicated account/client/folder.
Wait for that OAuth worker job to complete. Then run:

```bash
.venv/bin/python scripts/prove_drive_recovery.py \
  --dedicated-test-account --destination-id DESTINATION_UUID --phase reconnect \
  --execute --root-go ROOTGO
```

Reconnect requires a genuinely new grant and unchanged storage configuration.
It tests the saved destination and reopens the **same historical copy** with
the app's current SQL grant, comparing the complete file-map hash to the prior
Drive readback. It creates no new source backup. SQL-backed adapters already
use the current grant; do not seed an offline session from an old exported
kit. `OfflineSession`'s existing recovery store is authoritative unless an
owner explicitly supplies a fresh override.

An optional revocation test needs its own later scope approval. It is excluded
unless root supplies both `--revoke-dedicated-grant` and
`--revocation-go ROOTGO_REVOKE` in the reconnect phase. First reverify the valid
local point and source witness. Under the same credential locks/guards, CAS a
new local grant ID and revocation marker **before** contacting Google's revoke
endpoint, fencing old revision/grant writes. Retain the old grant only in a
bound encrypted checkpoint. Call Google revoke on that old grant, then make a
real Google refresh request with it and require safely classified
`STORAGE_AUTH_EXPIRED`. Confirm the source is unchanged and retain the local
point. The phase stops awaiting one fresh private UI Reconnect; rerun the
ordinary reconnect command to read back the historical Drive point. Do not
revoke a shared/personal grant, and never run this optional phase merely
because OAuth could be refreshed.

Before each long API POST, the harness persists its planned submission and
stable idempotency key. A lost response triggers lookup of that exact existing
job. If no unique job can be established, it stops for root review; it never
creates a substitute restore. Plan responses and confirmation tokens are
checkpointed privately, with tokens encrypted. Persisted failed,
`needs_attention`, rollback or timeout outcomes stay attached to their job;
reruns wait/reconcile that ID rather than requesting another destructive
operation. Policy cleanup failures are also recorded explicitly. Resolve the
product's uncertain operation before changing any checkpoint.

`docs/evidence/drive.json` is written only by actual execution, including failed
attempts and policy-cleanup state. It distinguishes storage readback,
application startup, refresh persistence, optional revocation and reconnect.
It never claims user login/decryption. This drill does not perform live
retention deletion, so its evidence leaves `AC14_release_verified` false until
the separate live retention requirement also has passing evidence. No live
Google behavior is verified by the preparation tests.

Pure preparation validation:

```bash
.venv/bin/ruff check scripts/prove_drive_recovery.py tests/unit/test_drive_drill.py
.venv/bin/python -m py_compile scripts/prove_drive_recovery.py
.venv/bin/python -m pytest -q tests/unit/test_drive_drill.py
```

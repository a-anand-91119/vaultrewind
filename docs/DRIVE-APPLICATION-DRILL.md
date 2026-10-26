# Independent Drive restore application readback

This is a read-only structural proof of an **already completed** synthetic
Drive-to-alternate restore. Preparation and unit tests do not prove the live
application. ROOT owns execution, all live connections, and all fixture changes.
The probe makes no Google Drive/provider calls and can run alongside an isolated
retention proof that does not schedule source or alternate jobs.

Preparation requires no credentials and opens no private files, SQL connection,
HTTP/SSH client, Docker process, repository, or runtime directory:

```bash
.venv/bin/python -m scripts.prove_drive_application_readback
```

After the restore is terminal **and its Drive drill checkpoint records the
completed alternate restore**, ROOT runs:

```bash
.venv/bin/python -m scripts.prove_drive_application_readback \
  --execute --root-go ROOTGO_READBACK --dedicated-test-account \
  --destination-id "$DRIVE_DESTINATION_UUID"
```

`--run-id "$DRIVE_RUN_UUID"` selects the exact existing checkpoint when its run
UUID differs from the destination UUID. The default run ID is the destination ID.
Both must be canonical UUIDs. There are no configurable source, target, origin,
endpoint, path, port, or repository overrides. ROOT must serialize any new source
or alternate operation until the probe finishes; it refuses active jobs and
rechecks the catalog, API job, and original checkpoint before publishing evidence.

## Required existing inputs and scope

The source UUID is `46ac8eb9-1854-4fc6-924f-af14c6b7d0c2`; the alternate UUID is
`b05f7958-3d3b-48d6-a8f2-8eb900533149`. The native controller connections come
only from existing `.runtime/controller/integration.json`, `database-url`,
`master`, `api-cookies.json`, and `vm-public-policy.json`. Only the existing
`.runtime/drive-proof/<run-id>/checkpoint.json` and
`drive_readback-restored/` supply checkpoint/content inputs. The script does not
construct `DriveDrill`, create a second checkpoint, or open storage adapters.

The existing `.runtime/vm/controller-loss-target-fourth.json` supplies the **admin
connection only**, pinned to `127.0.0.1:22229`. Its own profile UUID is
`02b09a69-7c5f-4695-85f5-8514364ca6f5`, distinct from the alternate being proved.
The alternate's actual profile in `vm-public-policy.json` supplies its fixed bind
root and container name, loopback HTTP binding `18100`, and sole permitted
configuration substitution, `DOMAIN`. SQL enrollment must independently bind to
the alternate's remote UUID and the same pinned host. The admin descriptor key
is imported in memory by AsyncSSH. Payloads travel on SSH stdin, never in argv.
SSH agent use/forwarding and ambient SSH configuration are disabled.

Private connection/checkpoint files must be existing regular, owner-only files
owned by the current account. Private directories must already exist with
owner-only access. Symlink path components are rejected; permissions are never
repaired. Existing snapshot content retains its captured metadata inside its
private readback directory. No credentials, manifests, row values, config values,
or raw transport/SQL errors are printed.

## What a passing execution proves

- Both checkpoint readbacks are complete and identify the same snapshot,
  manifest, complete file map, file count, and byte count. The alternate checkpoint,
  consumed restore plan, succeeded SQL restore job, selected Drive copy, source
  repository and explicit destination all agree. SQL uses read-only transactions
  and decrypts only the existing connection secrets without upgrades or writes.
- The actual API job has both public proof flags. Its current generation matches
  the target and restore operation, preventing an earlier successful restore from
  proving a later or different generation.
- `verify_snapshot` checks the existing Drive readback against the catalog
  manifest. The saved inventory document, full file map, byte count, snapshot and
  source IDs, image identity and saved-image SHA-256 must agree. The snapshot is
  a standalone normalized SQLite database, with no WAL/SHM companions.
- Expected counts for **all five** `users`, `organizations`, `ciphers`,
  `attachments`, and `sends` tables come from the captured SQLite database opened
  read-only. When captured `data/config.json` exists, its entire configuration and
  original UID/GID/mode are preserved, with only its `domain` value substituted
  from the approved target `DOMAIN`. Environment-only sources are also supported:
  config must be absent from both verified manifest and readback, with no symlink;
  the expected object starts as `{}` and receives only the approved `domain`.
  The generated target config must match that entire object and be root:root,
  mode `0600`. This follows `remote/overlays.py::apply_environment`, which restores
  prior metadata only when a prior file exists, and `remote/journal.py::atomic_json`,
  which creates mode `0600` under `helper.main`'s umask `077`. Installed helper
  sudo/systemd execution is root:root; restore rejects setgid directory modes.
- The SSH program reuses `scripts/prove_alternate_readback.py`'s `READBACK`
  constant verbatim. It checks every captured non-database persistent data file's
  SHA-256/UID/GID/mode; the entire overlaid configuration's canonical hash and
  captured or generated metadata contract; SQLite integrity and five table counts; the recorded image;
  target/operation labels; published bindings; `/alive`, `/api/config`, and the
  effective public URL. Additional guards reject symlinks, confirm the actual
  writable data mount, and ensure the container ID/start time stays fixed across
  inspection. Enrollment's original container ID is not used as the active
  generation: restore deliberately recreates the container.
- The existing operational SSH connection requests only helper `status` with the
  **current SQL fencing token**. It must report the same operation/instance/active
  generation, `complete`, `candidate_validated`, and both public proof flags.
- The recovery script's existing `source_witness` method is invoked without
  constructing its mutable drill/client. Its exact source Docker identity,
  running state, start time, and complete inventory hash must match the original
  checkpoint `source_before_restore`, and must remain identical before/after SSH.

The probe submits no job, backup, provider access, credential refresh, restore,
copy, cleanup, or target data/container change. There is no new plaintext download
and therefore no download cleanup. Existing readback staging and checkpoints stay
in place. Normal helper `status` is requested only for the already completed
operation; this is not a request to reconcile unfinished work.

## Evidence and limits

Only a successful actual execution exclusively creates
`docs/evidence/drive-application.json`, mode 0600. Preparation, tests and failed
proofs create no evidence. An existing report causes a refusal for ROOT review;
all prior reports are preserved. Output on failure is a public code, with raw
private exception details withheld. Re-running the same proof is read-only, but
publishing another report requires ROOT to review the existing evidence first.

The report explicitly makes **no Vaultwarden authenticated login, decryption,
or client synchronization claim**. It is structural content and application
startup/public-health evidence for this dedicated synthetic fixture. It does not
perform a fresh Drive read, replace real authorization/refresh/reconnect/retention
evidence, or by itself establish all of AC14.

## Harness-only failed attempt

ROOT's first actual read-only probe raised `FileNotFoundError` in `build_payload`
at its then-line 282 while reading `data/config.json`. The verified snapshot had
its control files, database, and saved image; the supported manual,
environment-only source correctly had no config file. This was a harness
assumption, not a product restore failure or application mutation. ROOT reported
the alternate restore still succeeded, public health returned HTTP 200, and the
source remained unchanged. No successful application evidence was created.

The correction explicitly verifies source config absence and the helper's
generated target config content/metadata, while retaining all captured-config
checks and the shared `READBACK` constant. Synthetic regressions execute the real
helper overlay on a separate temporary target, then run that shared readback
with mocked Docker/HTTP responses. These tests do not claim a successful live
rerun; ROOT owns that execution. The generated root:root regression requires
root execution and is skipped when the unit-test account is not root:root.

Pure local validation, limited to the new files:

```bash
.venv/bin/ruff check --no-cache scripts/prove_drive_application_readback.py tests/unit/test_drive_application_drill.py
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -q -p no:cacheprovider tests/unit/test_drive_application_drill.py
```

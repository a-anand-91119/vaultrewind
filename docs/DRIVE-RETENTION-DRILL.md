# Dedicated Google Drive retention drill

Execution requires an owner-authorized dedicated test account and the coordinator's
separate `ROOTGO_LIVE_RETENTION` release. Consult [ACCEPTANCE.md](ACCEPTANCE.md)
for recorded live evidence; this procedure and its pure tests establish none.
Preparing this script and running its pure tests,
compiler and Ruff checks performs no live API, PostgreSQL, provider, network,
SSH or Docker action. Do not run a live test to validate preparation.

`scripts/prove_drive_retention.py` defaults to printing a prepared/not-run
record to stdout. It creates no private files, SQL engine, credential store,
runtime directory, or public evidence. Even a supplied release word has no
effect without `--execute`. Execution requires **all** of these:

- `--execute --root-go ROOTGO_LIVE_RETENTION`;
- `--dedicated-test-account` and the exact authorized app destination UUID;
- `--run-id` matching an earlier genuine dedicated-account recovery drill;
- an explicit fixed future UTC `--planner-time` for isolated fixture planning.

Preparation, with no known destination or credentials, is safe:

```bash
.venv/bin/python scripts/prove_drive_retention.py
```

This document grants no execution authorization. Never ask for secrets in
chat or put tokens/client secrets in command arguments. All OAuth setup and
Reconnect input belongs in the app's existing private forms.

## Boundary and prerequisites for the later authorized run

This is a **direct product retention-planner and provider-adapter proof**, not
an API/SSH production workflow. It uses the real product
`retention_preview(..., current=fixed_fixture_time)`, `SQLCredentialStore`,
Drive credential sessions, restic and rclone. It does not submit backup,
restore, retention or deletion jobs to the native API. It never stops a source,
connects through SSH, invokes Docker, changes the controller clock, changes a
native policy, or updates native snapshot/copy capture times.

Root must first complete the separate authorized recovery roundtrip in
`docs/DRIVE-DRILL.md` using the dedicated account and exact destination. Its
private checkpoint and complete local readback must be available at:

```text
.runtime/drive-proof/<recovery-run-UUID>/checkpoint.json
.runtime/drive-proof/<recovery-run-UUID>/local_readback-restored/
```

When that drill omitted `--run-id`, its run UUID equals the destination UUID;
use that UUID here too. The readback contains the already captured synthetic
Vaultwarden bytes, including encrypted vault records, attachments, Sends,
configuration, keys, deployment, saved image and complete file manifests.
The retention harness verifies its original manifest, image and SQLite before
copying it. It accepts no arbitrary input path. It does not mutate the input
tree, native source, actual Drive historical roundtrip copy, or its catalog.

Root serializes this run with all other work using the destination. The
harness requires the existing SQL `credential:<destination-UUID>` resource
row to have no owner, including an expired owner; it holds that row locked
with `NOWAIT` for the whole provider drill. It rejects pending encrypted
credential updates and every registered Drive session, including orphaned
sessions, before proceeding. Resolve these through product recovery first.
It never force-unlocks a resource or deletes a recovery journal.

The persistent credential-state directory must exactly match the worker's
configuration: `settings.provider_credential_state_dir`, or by default
`settings.staging_dir.parent / "provider-credentials"`. For the native layout
this is `/srv/vaultrewind-native-controller/provider-credentials`. The optional
`--credential-state-dir` flag is only for a root-verified explicit override.
Using another directory would create the wrong lock/recovery namespace.

Provider sessions load the current encrypted native SQL credential, retain
the destination's grant/generation/configuration binding, and persist rclone
rotations using the product's generation-and-revision CAS and session locks.
The harness does not inject expiry, force OAuth refresh, revoke a grant, test
quota, select an account, or seed credentials from a recovery kit. Real Google
quota and revocation scope belong to the other harness. A dedicated account
is an owner acknowledgement, not an independently verified identity claim.

## Disposable scope and exact expiration

Each first execution creates an exclusive private directory:

```text
.runtime/drive-retention/<recovery-run-UUID>/
```

Existing directories are rejected. Repository/instance/snapshot/copy UUIDs
are generated internally, never accepted from CLI overrides. The harness
checks them against native catalog identities and rejects any collision,
including the enrolled source and alternate. It lists the existing Drive
layout root and requires both new instance prefixes to be absent before
initialization. Initialization must report `created: true` and an empty
snapshot set. Opening an existing repository is never accepted.

There are two separately new fixture instance/repository pairs under the
already authorized dedicated destination:

```text
<dedicated folder>/vaultrewind/<new fixture instance UUID>/<destination UUID>
<dedicated folder>/vaultrewind/<new sentinel instance UUID>/<destination UUID>
```

Both are disposable. The sentinel belongs to the second new fixture instance;
the deletion path can address only the first. No historical repository is
opened for mutation. Each has a unique random restic password, encrypted in
the private checkpoint for reconciliation. Provider repository IDs are bound
immediately after creation.

Private independent copies of the original verified tree become seven new,
clearly labelled retention fixtures. Their **synthetic capture times** and
new identities are written only when creating these fixtures and inserting
their isolated SQLite catalog rows. The original immutable rows and manifests
are untouched. The cloned manifests explicitly describe this fixture method;
they do not claim another real historical capture. Each clone also has unique
private disposable bytes so forgetting/pruning can exercise unreferenced
content, with a newly complete file inventory. No extra source backup is needed.

At the selected future fixture time, with 30-day retention:

- One point is one second before the cutoff and is eligible.
- One point is exactly on the cutoff and stays retained.
- Two more points are one and two seconds inside the window; both stay retained.
- An older pinned point stays protected.
- The newest complete point stays protected.
- The other instance's point is in its separate sentinel repository.

The first pass forgets only the one expired point's full 64-character restic
ID. The second pass supplies a separate explicit fixture time 31 days later.
Every fixture point is then older than the cutoff, so the planner must expire
only the former boundary and two within-window points. The old newest complete
point and old pinned point must still survive their actual protections.
Snapshot capture times are never rewritten between passes. Neither pass
changes the native controller's time or invokes a native retention worker.

Each pass recalculates the real product plan immediately before forgetting,
checks freeze reasons/policy revision/protections, maps exact copy IDs to the
bound repository's full restic IDs, and records intent durably before deletion.
Provider snapshot sets must match the known fixture catalog exactly. Unknown,
foreign, missing or changed identities stop the drill. Deletion must report
exactly the requested IDs removed, no retained/already-absent IDs and a clean
exit. A permission failure is not success.

After each exact forget, the harness verifies the exact remaining provider
set, prunes that new repository with a structural check, and performs a full
`restic check --read-data`. It restores **every retained point** from Drive
into a fresh private directory using `restore --verify`. It verifies the
catalog-bound manifest, inventory sidecar, every file hash/path, SQLite
integrity/attachment references, standalone normalized database and saved
image hash. It verifies a full sentinel restore before and after both passes
and compares the complete file map and identities. It does not boot another
container or claim application startup/login/decryption verification.

Forgetting, pruning and account quota are different observations. The evidence
does not claim a particular amount of physical provider space was reclaimed;
Drive trash/provider behavior can affect that. No quota API is called.

## Later command — root release required

Only after the specific release and prerequisite review, substitute the two
nonsecret canonical UUIDs below. Pick and record a future fixed UTC fixture
time more than one year ahead; `2040-01-31T12:00:00Z` is an example, not an
instruction to alter any clock.

```bash
.venv/bin/python scripts/prove_drive_retention.py \
  --dedicated-test-account --destination-id DESTINATION_UUID \
  --run-id RECOVERY_RUN_UUID --planner-time 2040-01-31T12:00:00Z \
  --execute --root-go ROOTGO_LIVE_RETENTION
```

All private trees, manifests, passwords and checkpoints remain owner-only.
The script withholds raw provider/SQL exception details and checks public
evidence against the credential values it observed. It retains the workspace
even on success. Do not indiscriminately remove it: product pending/config/
orphan recovery can hold the only usable rotated credential.

An interrupted init/commit/forget/prune/restore is **not automatically resumed**.
The same run directory prevents retrying an ambiguous destructive operation.
Preserve its checkpoint, encrypted repository secrets, isolated catalog,
adapter directories and global credential state. Root must reconcile the
recorded exact repository and snapshot IDs with product recovery, and prove
no provider process remains active, before authorizing any further action.
Do not change run IDs to evade that recovery. Cleanup/deletion of the remaining
protected disposable repositories needs a separately reviewed exact scope.

## Evidence and preparation checks

Only a fully successful live execution writes
`docs/evidence/drive-retention.json`; preparation writes no such file. Partial
and uncertain outcomes remain in the private checkpoint and return nonzero.
The public report contains matched run/destination/configuration/input IDs,
exact deletion sets, prune/full-check results and complete retained readback
proof. Existing public retention evidence is never overwritten automatically.

This independent proof always leaves `AC14_release_verified: false`.
`scripts/prove_drive_recovery.py` is unchanged and retains its honest false
aggregate. The [completed aggregate](evidence/drive-release.json) matches these
run/destination/configuration/input identities with actual OAuth authorization,
persisted refresh, local/Drive readback, application restore, Reconnect and
separately authorized revoked-token evidence. Preparation alone establishes none
of those observations; future runs need their own matched, completed reports.

Allowed lightweight preparation checks:

```bash
.venv/bin/ruff check scripts/prove_drive_retention.py tests/unit/test_drive_retention_drill.py
.venv/bin/python -m py_compile scripts/prove_drive_retention.py tests/unit/test_drive_retention_drill.py
.venv/bin/python -m pytest -q tests/unit/test_drive_retention_drill.py
```

The tests use an in-memory disposable SQLite catalog and the actual product
planner, plus recording fakes for ordering/failure contracts. They prove flag
gates, rolling boundaries, newest/pin protections, failure freezes, exact-ID
mapping and instance isolation. They provide no live Google evidence. No
Docker, heavy-CPU suite, live SQL or network run is part of preparation.

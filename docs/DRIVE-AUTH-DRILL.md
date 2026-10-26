# Dedicated Drive worker authorization failure and same-snapshot retry

This drill covers AC14, AC18 and the credential-failure part of AC26. It uses the
actual API and worker to capture once with a required local copy and a required
Drive copy whose dedicated credential has already been revoked. After the owner
uses Reconnect in the private UI, it retries that exact failed copy. It does not
claim user login, application startup, quota testing or complete AC14 release
verification.

Implementation and pure verification do not authorize execution. ROOT exclusively
owns live API, SQL, provider, SSH, Docker and source/VM mutation slots. Run these
commands only from ROOT's serialized, explicitly released slot. This harness
provides no OAuth authorization, credential edit, expiry injection, Google
revocation or Google OAuth refresh operation. The original recovery harness and
private UI own those actions. Product repository sessions during the repaired
Drive readback may refresh/persist credentials through their normal context.

## Preparation and execution contract

From the project root, pure preparation is:

```sh
.venv/bin/python -m scripts.prove_drive_auth_failure
```

It creates no runtime directory, opens no private file, constructs no HTTP/SQL or
provider client, makes no subprocess call and writes no evidence. Both module
and direct script invocation are supported. The new script imports only standard
library code and the original harness's pure helpers at preparation time; it never
constructs `DriveDrill` or writes `.runtime/drive-proof`.

ROOT must supply all six execution requirements: `--execute`, the exact
`--root-go ROOTGO_AUTH_FAULT`, `--dedicated-test-account`, `--destination-id UUID`,
`--run-id UUID` and `--phase fault|retry`. The run UUID must match the earlier
recovery and retention run. There is no new-run, origin, target, restore path,
credential path, native-catalog time or force/retry override.

The only controller origin is `http://127.0.0.1:8098`. Settings use the existing
native private PostgreSQL URL, master/bootstrap files and API cookies from
`.runtime/controller`. PostgreSQL must be local. Staging and local storage are
fixed beneath `/srv/vaultrewind-native-controller`; global provider recovery
state is `/srv/vaultrewind-native-controller/provider-credentials`. No separate
per-drill credential recovery directory is allowed. ROOT must confirm that this
is the native worker's configured global state directory before releasing work.

The only source is `46ac8eb9-1854-4fc6-924f-af14c6b7d0c2`. A read-only Docker
inspect must identify the exact current name `/vr-ssh-source`, its source UUID
instance label, and exactly one `/data` bind from
`/srv/vaultrewind-fixtures/source/data`. Source and native local root paths must
be real paths. Source mutation occurs solely through the worker's Backup now
operation. This harness invokes no SSH operation or Docker mutation and never
performs a target restore.

`Instance.container_id` is the historical enrollment ID. An untouched source
with no catalog `active_generation` must still match that ID and have no operation
or generation-role label. A restored source must carry the catalog generation in
`org.vaultrewind.operation` and have `org.vaultrewind.role=active`, even when its
enrollment ID differs. Its catalog generation must identify a real succeeded
source restore job with complete content, activation and running-source outcomes,
matching target and result generation, positive current fencing token and the
recorded validation/startup/verified-byte flags. The local helper restore journal
must match that current job/fence, source, active generation, final Docker ID and
fixed name, with complete phase and disarmed watchdog. These are read-only checks;
no historical job, enrollment field, helper journal or image is changed. Wrong
generation, foreign labels, wrong physical root and stopped sources remain hard
failures. Actual current Docker ID and generation/fence are recorded in each
witness and must remain unchanged across both fault and retry.

## Required prior evidence

The harness reads the existing
`.runtime/drive-proof/<run-UUID>/checkpoint.json`; it never rewrites it. Required
bindings include source, destination, run, base snapshot, complete local and Drive
copies, matching manifest/file-map hashes, successful persisted real refresh,
completed alternate restore and restored original policy.

`docs/evidence/drive-retention.json` must report both live retention rounds
complete, with the same run, destination, input snapshot/manifest and Drive
configuration fingerprint. The original recovery harness must also have finished
its optional dedicated-grant revocation phase and recorded:

```text
revocation.locally_invalidated = true
revocation.google_revoke_acknowledged = true
revocation.actual_google_refresh_error = STORAGE_AUTH_EXPIRED
revocation.source_unchanged_and_local_copy_verified = true
```

The fault phase requires the SQL credential still to be locally revoked. Its
unchanged token/client/folder/scope fields must match the original harness's
encrypted revoked credential. The original harness changes the local grant ID
when invalidating it; this drill records that local revoked grant separately
from the original Google grant hash. No credentials are changed here.

## Fault phase

ROOT substitutes the dedicated destination and the matching existing run UUID:

```sh
.venv/bin/python -m scripts.prove_drive_auth_failure \
  --execute --root-go ROOTGO_AUTH_FAULT --dedicated-test-account \
  --destination-id "$DRIVE_DESTINATION_UUID" --run-id "$DRIVE_RECOVERY_RUN_UUID" \
  --phase fault
```

Before submission, the harness requires no active source/physical-source job,
no credential lease owner or active destination job, no pending credential
update and no registered Drive session. Such state is a product recovery task;
the harness does not scrub it or force-unlock it. It verifies the historical
local copy through product `Adapters`, including restic `restore --verify`,
manifest identity, saved-image hash, standalone SQLite integrity and full
manifest file-map hashes. It records source running state, container start time,
logical SQLite data, non-database bytes, ownership/link metadata and source helper
journals using read-only inspection. Logical SQLite reads include WAL content.

The policy must remain DISABLED and match the recovered original. It must have
a required local destination at `/srv/vaultrewind-native-controller/backups`.
A revision-guarded API PATCH preserves every original destination and required
flag, schedule, timezone, runner, retention setting and budget, adding or marking
the selected Drive destination required. It records restoration intent before
the PATCH. Disabled state is preserved; this is a manual Backup now.

There is one durable Backup now submission. Passing requires the actual worker
job to be `partial`, with `content_commit=complete`,
`required_copy_outcome=failed`, `source_service_outcome=running`, the expected
local repository's copy `complete`, and the selected Drive copy `failed` with
`STORAGE_AUTH_EXPIRED`. Any different actual result fails honestly. The harness
does not force job states, alter results or capture again to get a desired result.

The exact new snapshot, local copy, failed Drive copy and Drive repository IDs
are retained. The fault snapshot's local copy receives the full readback proof.
The source's logical database and non-database content/metadata must remain
unchanged across the controlled capture; the expected source restart and new
helper journal are allowed in this phase. The historical local recovery point is
verified again. The exact original policy, including DISABLED, is restored in
`finally`; original verification/test scheduling fields must remain unchanged.
Historical Drive readability is **not** asserted using the revoked grant.

## Reconnect and retry phase

After the fault phase passes and restores policy, the owner completes Reconnect
for the same destination in the private UI. ROOT releases the retry slot:

```sh
.venv/bin/python -m scripts.prove_drive_auth_failure \
  --execute --root-go ROOTGO_AUTH_FAULT --dedicated-test-account \
  --destination-id "$DRIVE_DESTINATION_UUID" --run-id "$DRIVE_RECOVERY_RUN_UUID" \
  --phase retry
```

The SQL grant must be nonrevoked and have a grant ID different from both the
Google grant revoked by the recovery harness and the recorded local invalidated
grant. The Drive configuration, source configuration and historical baseline
must match. Retry never installs a policy or calls Backup now. Its only job
submission is:

```text
POST /api/v1/snapshot-copies/<recorded-failed-Drive-copy-ID>/retry
Idempotency-Key: drive-auth:<matching-run-UUID>:retry
{}
```

The durable job plan binds `kind=retry_copy`, the exact snapshot and repository,
and `original_job_id` from the original partial backup. SQL reconciliation
checks this plan before accepting an ID. Passing requires retry `succeeded`,
the same snapshot and both original copy IDs complete. A full Drive restore and
manifest/file-map proof must match the fault's verified local copy. The fresh
grant also reads the base historical Drive point and compares its bytes with
the recorded baseline.

Container ID, `StartedAt`, full source inventory, logical database,
non-database bytes/metadata and local source helper journal count/content must
all remain unchanged across retry and readbacks. The original partial job's
terminal fields and error must remain unchanged. The script never deletes
failed jobs, attempts, events, journals, immutable captures or provider recovery
work. A failed retry is retained for ROOT inspection; a new CLI run ID does not
provide an automatic second attempt.

## Durability, errors and evidence

Private state is separate:
`.runtime/drive-auth-fault/<matching-run-UUID>/checkpoint.json`. An exclusive
global drill lock prevents concurrent invocations. Other runs for the same
destination with submissions are rejected, so changing the UUID cannot bypass
an ambiguous request. A checkpoint with the same revoked grant under another
run is also rejected.

There is one narrow compatibility migration for the earlier preflight guard that
incorrectly compared a restored source against its historical enrollment ID.
Only a checkpoint missing `source_configuration.active_generation` can add the
current catalog field, and every existing binding field must agree exactly.
It requires the original `EXACT_RUNNING_SYNTHETIC_SOURCE_REQUIRED` fault failure,
the complete bound `base_before_fault` local readback, an empty steps map, no
policy intent/original-policy record, no source-before witness, no newly captured
snapshot/copy IDs and no later-phase proof. Even a recorded unattempted job plan
blocks this migration. An existing or changed generation is never rebound.
The migration adds only that field, preserves the initial failure/readback and
all history, and keeps the same run UUID. ROOT need not erase or hand-edit state;
normal released execution saves the addition after the remaining catalog guards
pass, then independently verifies the current Docker generation before policy
installation or job submission. Preparation and pure tests do not migrate files.

Stable keys end in `:fault` and `:retry`. Submission intent and the immutable job
plan are saved before POST. A lost response is reconciled through SQL job and
idempotency alias records. Zero or multiple matches stop with
`SUBMISSION_RESPONSE_UNRESOLVED_DO_NOT_REPEAT`; no POST is repeated, even if
the original request never reached the API. A known ID is also checked against
its plan. ROOT must reconcile the preserved record, rather than erase it or
choose a different run UUID. Interrupted restic readbacks preserve their work
and stop; the script never scrubs a directory that could contain pending or
orphan credential recovery state.

Policy cleanup runs after failures. If the recorded job is still active, cleanup
cannot safely PATCH: the script reports partial evidence and preserves the job
ID and restoration intent for ROOT. Concurrent policy changes are not overwritten.
Lost PATCH responses are reconciled by reading the current policy. Original
operation and cleanup errors are retained together. Where the source is idle,
final checks reverify the historical local bytes and source witness even after
an unexpected actual fault result.

Only actual execution writes `docs/evidence/drive-auth-failure.json`. It reports
`partial` until both phases and exact policy restoration pass in a successful
execution. Evidence contains IDs, safe states/errors and hashes; credentials and
manifests stay private. stdout contains code and safe state enums only. The
report keeps `user_login_tested=false` and `AC14_release_verified=false`.

Pure validation:

```sh
.venv/bin/pytest -q tests/unit/test_drive_auth_drill.py
.venv/bin/ruff check scripts/prove_drive_auth_failure.py tests/unit/test_drive_auth_drill.py
.venv/bin/python -m py_compile scripts/prove_drive_auth_failure.py tests/unit/test_drive_auth_drill.py
```

These checks provide implementation evidence only. ROOT must inspect and execute
the guarded live phases before claiming the worker auth-failure/retry drill passed.

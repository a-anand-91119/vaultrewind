# Required-copy recovery and attachment-heavy worker drill

This drill exercises the real loopback API, PostgreSQL queue and scheduler,
worker, constrained SSH helper, Docker Vaultwarden source, local restic and
MinIO. It covers AC18, AC02 and the root-owned mode-0600 attachment requirement
in AC03. The results are written to
[worker-copy-recovery.json](evidence/worker-copy-recovery.json) and measured
timings to [performance.json](evidence/performance.json) only after all checks
pass. These are synthetic engineering results, not a production speed promise.

The fixture is the enrolled `vr-ssh-source` container with data under
`/srv/vaultrewind-fixtures/source/data`, source UUID
`46ac8eb9-1854-4fc6-924f-af14c6b7d0c2`. The harness checks the exact source ID,
container fixture/managed-instance label, bind mount, existing attachment
reference, root ownership and mode before changes. It accepts only the known
local API and MinIO endpoint. It does not connect to the owner's server.

Run preparation while other work owns the source:

```bash
.venv/bin/python scripts/prove_worker_copy_recovery.py
```

Preparation reads current fixture metadata and API state, validates imports and
reports whether the credential PATCH route is live. It never queues work,
changes policy or changes source bytes. Private preparation/checkpoint files
stay under `.runtime/copy-proof/reference` with restricted access.

After the coordinating root agent explicitly sends `ROOTGO`, and its original
source restore is finished, execute:

```bash
.venv/bin/python scripts/prove_worker_copy_recovery.py --execute --root-go ROOTGO
```

The flag records a coordination release; it does not grant authorization to
other hosts. All fixture guards still apply. The required destination detail
GET and revision-guarded PATCH routes must already be wired into the running
API. Do not restart another agent's API or worker to enable them.

1. Preserve the current API policy and its disabled schedule. Extend the one
   existing 28-byte synthetic attachment to exactly 16 MiB with deterministic
   bytes, preserving its owner, group and mode. Update only that referenced
   attachment's SQLite `file_size` so the synthetic application metadata is
   consistent. Record bytes, SHA-256 and numeric ownership. This is explicit
   fixture setup, not an application backup mechanism.
2. Create a required S3 destination at the real loopback MinIO endpoint and
   synthetic bucket using deliberately invalid synthetic access credentials.
   Keep the required valid local destination. Do not use an unreachable URL:
   a physical storage identity cannot be changed once historical repositories
   exist, whereas credentials can be repaired without moving content.
3. Submit one manual backup through the API. The actual worker must report
   `partial`, independently record required-copy failure and source recovery,
   and leave a complete local copy. Restore that exact local copy into an empty
   private readback directory through the application's restic adapter and
   verify the complete manifest, database integrity, attachment bytes and hash,
   mode and UID. No source replacement is involved in this readback.
4. Repair only the S3 credentials through the actual destination PATCH using
   the current `If-Match` revision. Request Test destination through the API;
   wait for its real write/read/delete probe job. Secrets are read from private
   files into memory and never printed, passed in argv or written into public
   evidence. No SQL secret replacement counts as credential repair evidence.
5. Submit Retry for the failed copy. Verify it uses the same snapshot UUID,
   leaves the source container `StartedAt` and source helper-journal count
   unchanged, and completes the cloud copy. Independently restore and verify
   both cloud and local copies. Stored manifest inspection alone is not
   described as a full repository data check.
6. Enable the ordinary backup policy through the API. Change only this exact
   fixture policy's `next_run_at` to one second in the past as a test clock
   injection. Let the running scheduler create the occurrence and queue the
   actual worker job. Require a distinct scheduled snapshot UUID, two complete
   copies, and an identical complete inventory map of regular-file paths to
   SHA-256 values, including identical normalized database bytes. Capture time,
   snapshot identity and regenerated database mtime are not file-content
   differences. No capture is implemented by the harness.
7. Restore the original policy through the API, including disabling its
   schedule. Keep the new destination, repositories and both recovery points
   available. The attachment-heavy synthetic fixture can remain for further
   evidence. It is not necessary to erase the test content or replace the
   source again.

Checkpointed API job IDs prevent duplicate submissions. A failed or interrupted
run retains private state for diagnosis; inspect current jobs before resuming.
An active ambiguous operation must be reconciled through the product, not
discarded by deleting the checkpoint. The harness attempts original policy
restoration after terminal jobs; an unresolved source operation can block that
cleanup and must be reported explicitly.

Performance reports distinguish HTTP job-creation latency, persisted progress
visibility, queue time, worker time and each recorded phase. Capture outage is
a conservative upper bound from the helper's `quiescing` transition through
verified source recovery to `validating`, including stop/start overhead. Raw
copy and staged sealing times are separate. Transfer/copy timing comes from
durable worker events; stored bytes are the actual restic packed-data counts,
so deduplication can make them much smaller than logical bytes. Local and cloud
readback durations include restic `restore --verify`, with a separate repeated
manifest/database verification duration.

The normalized database must pass integrity and reference checks and have no
WAL/SHM companion in the recovery tree. `wal_incorporated` reports the product's
normalization method; a nonempty source WAL is separately observed and must not
be inferred merely from that flag. This drill does not claim authenticated
Vaultwarden login, client decryption, a replacement restore, fresh-controller
recovery or Google Drive verification.

The recorded 25 October 2026 run passed AC02, AC03 and AC18. The manual and
scheduled snapshots contain identical SHA-256 values for all nine regular
inventory files, including the normalized database. Their logical size is
320,123,297 bytes. The helper outage upper bounds were 12.392 and 33.380 seconds;
verified local readback took 13.600 seconds and cloud readback 12.334 seconds,
followed by separate manifest/database checks of 2.420 and 2.847 seconds.
Manual and retry API creation took 0.975 and 1.853 seconds. Persisted queued
progress appeared in 0.018 and 0.020 seconds; the retry's first named work phase
appeared after 8.071 seconds. These measurements include shared-host contention.

The first run also exposed a limitation: MinIO rejected the deliberately bad
keys with HTTP 403 in 0.501 seconds, but restic repository opening continued
until `STORAGE_TIMEOUT`. The product conservatively recorded the cloud copy as
`uncertain` and the overall job as `partial`. The harness initially required
`failed`, stopped and restored the original policy. That failed assertion is
retained in evidence. Continuation accepted the truthful uncertain-copy state,
verified the local copy, repaired credentials through PATCH and completed the
same snapshot's cloud copy without another source pause. Fast, accurately
classified credential rejection remains unproven by this run.

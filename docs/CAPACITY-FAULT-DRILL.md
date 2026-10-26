# Controller and storage capacity fault drill (AC26)

Run from the repository with the locked Python environment and real restic installed:

```sh
uv run python scripts/prove_capacity_faults.py
uv run pytest -q tests/unit/test_capacity_faults.py
```

The JSON evidence is [evidence/capacity-faults.json](evidence/capacity-faults.json).
This drill supplies focused controller/storage evidence for ROOT's AC26 decision.
It does not declare all AC26 requirements complete.

## Isolation and scope

Every invocation creates a new mode-0700 `/var/tmp/vr-capacity-*` directory, a new
SQLite controller database/schema, random instance and snapshot UUIDs, private
master/repository keys, independent restic repositories and an ephemeral
loopback HTTP server. It never accepts existing source paths, DB URLs, endpoints,
container names or credentials. `/var/tmp` must be on a supported persistent
filesystem for the local mount test; `/tmp` on this host is tmpfs.

When the existing local `vaultrewind:0.1.0` image is available, the script creates
one uniquely named inert Docker process, with no network, no published ports,
no capabilities, a read-only root filesystem and a read-only bind of the new
synthetic source. It checks that the process remains running with the same
container ID, start time, restart count and source content digest after each
fault. The script removes only this new container after the final observation.
`--no-docker` records a limitation and performs source byte checks alone.

**The source is an application-shaped SQLite fixture and an inert process, not
a running Vaultwarden application or an enrolled SSH source.** These tests call
the actual controller `Context.reserve`, `Context.extract`, queue/fence methods
and `Worker.failure`; they do not execute an API-to-SSH backup job. This evidence
does not establish source watchdog, boot recovery, full backup orchestration or
application startup correctness. The snapshot image member explicitly contains
a capacity-only placeholder. It is not a saved Docker image, and successful
restic restoration here does not imply a deployable application restore.

Controller boundary jobs use the test-only kind `capacity_fault`, so failure
settlement exercises the real generic worker/queue cleanup without constructing
SSH connections. Their terminal-state assertions do not prove backup-specific
remote journal reconciliation or preflight rejection through the public API.

No production/native controller, existing SSH/VM/source fixture, shared MinIO
state or service is changed. No packages are installed or images pulled. Each
external command and restic operation has a 30-second timeout; waits are bounded.

## Faults and assertions

1. **Per-job and global logical quotas.** Actual `Context.reserve` rejects a
   minimum greater than the per-job quota, then rejects a reservation exceeding
   the global quota. No operation staging directory or allocation is created on
   rejection. Separate unit tests exercise two real claimed jobs and prove a
   retained retry capture continues to consume quota without eviction.
2. **Logical archive expansion.** Actual `Context.extract` passes the remaining
   operation budget to the real safe extractor. An oversized archive fails
   `STAGING_QUOTA_EXCEEDED` before member content is written. The compressed
   archive unit test verifies the bound applies to expanded bytes.
3. **Physical controller full staging.** A new private tmpfs is mounted with an
   8 MiB maximum. The actual controller reserves space while it is empty, then
   a bounded filler fills only that mount. The script requires a real errno 28
   (`ENOSPC`) and zero free bytes before calling actual `Context.extract` on a
   previously created valid archive. Extraction must fail with errno 28 in its
   causal chain. A subsequent real `Context.reserve` must reject the exhausted
   filesystem with `INSUFFICIENT_SPACE`. The controller DB and older repository
   are outside the full filesystem. Partial operation staging is cleaned and
   its allocation released.
4. **Physical missing local mount and read-only mount.** The script self-binds
   a dedicated new persistent directory, initializes its real destination marker
   and commits an older restic snapshot there. Remounting only this bind mount
   read-only must cause the operational validator to reject it with
   `STORAGE_READ_ONLY`; the explicit read-only recovery provider must still
   restore and fully check its older snapshot. Removing this run's bind mount
   must cause the operational provider to reject with `LOCAL_MOUNT_MISSING`
   using real `/proc/self/mountinfo`. The marker is retained throughout. No
   synthetic mount table or renamed/deleted marker manufactures the result.
   A self-bind exposes the same underlying files after unmount; this proves
   the dedicated-mount guard rather than a disappeared external disk. Namespace
   and byte hashes must remain identical, and recovery must still read the old
   repository. No empty replacement repository is created.
5. **Cloud quota through real restic.** A bounded in-memory synthetic S3 object
   service runs only on `127.0.0.1` at an OS-assigned port. Real restic first
   initializes and commits an older snapshot through HTTP. Enabling quota causes
   real PUT requests to receive HTTP 403 with S3 XML `QuotaExceeded`; actual
   `ResticRepository.commit` must fail. The first
   rejected write can be a repository lock; this tests commit failure at the
   provider-write boundary rather than exhaustion during a pack upload. Every
   old object must retain its original hash. Read-only real restic list,
   manifest read, full data check and verified restore must continue to work
   while quota rejects writes. This synthetic service accepts fixture
   credentials without checking request signatures. It proves quota response
   handling and preservation; it is **not live Google Drive, AWS or MinIO quota
   evidence**.

   Restic 0.19.1 retries this provider quota response when creating its lock.
   With this drill's bounded operation deadline the observed adapter result is
   `STORAGE_TIMEOUT`, not `STORAGE_QUOTA_EXCEEDED`. The artifact records the
   actual HTTP quota rejections, verifies preservation and read-only recovery,
   and marks this case `preservation_passed_with_adapter_timeout`; the overall
   result remains `partial`. It does not claim actionable quota classification
   or required-copy job reconciliation was verified.

Every passing case requires unchanged source bytes/process state and a real
restic list, manifest hash comparison, `check --read-data`, and verified restore
of the older local snapshot. Exact local repository file-byte hashes and the
snapshot set must remain unchanged. The mount and cloud cases additionally
verify their own older repositories. Failed controller boundary jobs must reach
`failed`, have no active jobs left in the private database, and release their
operation allocations. Mount-provider rejection is a read-only preflight call
with no job enqueued and no source control calls.

The script records physical mount setup denial as `blocked` and continues the
logical quota checks. It never fills an existing/shared filesystem or relabels
a logical quota failure as physical ENOSPC. Mount cleanup verifies the exact
mount ID belongs to this run before unmounting it.

## Evidence outside this drill

Source disk/free-reserve protection is owned by the separate remote/Astra
fixture drill. Existing [worker-copy-recovery.json](evidence/worker-copy-recovery.json)
contains AC18 API/worker/SSH/restic/MinIO invalid-credentials 403, required-copy
uncertainty/timeout and local-restoration evidence. That artifact is an existing
reference; this script does not replay or mutate its fixtures. Real expired
Google Drive credentials remain user-deferred. Neither that evidence nor this
artifact closes every expired-credential/live-provider part of AC26.

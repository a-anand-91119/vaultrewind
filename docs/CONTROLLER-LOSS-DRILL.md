# Fresh-controller recovery drill (AC30)

The drill uses the independently encrypted kit, retained repository disk, and a new PostgreSQL controller. It never restores the old controller database or reads its master key. The old controller may remain running; its existence is not a recovery prerequisite.

`docs/evidence/controller-loss.json` records each completed stage separately. Offline byte recovery and protected catalog import do not establish application startup. AC30 is complete only when the restored application also passes the helper's candidate validation and activation checks.

The recorded synthetic run passed authenticated kit export, independent offline discovery/verified byte restore, and the fresh PostgreSQL/HTTP API import. Readback found two snapshots, two repositories (one application and one controller), and one application placeholder. Both snapshots retained import-review holds; the safety snapshot also retained its safety hold.

The first application attempt, on the third target, passed internal candidate validation and activation, and its worker/helper reported completion. Independent published HTTP readback found a real readiness failure: the running container had the configured port binding and exposed port, but Docker reported no published ports on its internal bridge, and the expected `/alive` connection was refused. AC30 was kept partial. That failed-public-readiness attempt remains separately recorded in `application_attempts`; its activated data was preserved, with no restart, restore retry, or rollback.

After the helper gained public-network preflight and publication/HTTP postconditions, a separately authorized fourth empty target on a non-internal bridge passed the complete drill. Actual preflight reported `restore_ready: true`; the API/worker and helper recorded both `public_ports_verified` and `public_endpoint_verified`. Independent readback passed published `/alive` and `/api/config`, the approved target URL, exact saved image and target labels, all six captured non-database regular-file hashes, SQLite integrity and five selected synthetic table counts. All six pre-existing helper journal hashes remained unchanged. The original controller database and master key were never passed into the fresh stage; the old private-directory read guard recorded zero access attempts. AC30 is now recorded as passed. Authenticated user login was not tested.

Enrollment also queued a probe of the new controller's unused backup directory, which failed with `LOCAL_MOUNT_MISSING`. That separate observed job is recorded in the evidence. This drill has not verified new backup/safety capacity; the attempted restore used an empty target with no prior application data to capture.

## Boundaries and prerequisites

Use synthetic data and disposable infrastructure. This procedure is not authorization to change any production Vaultwarden server. The implementation fixture is a previously captured real Vaultwarden application, saved Docker image, normalized SQLite database, deployment descriptor, attachments, Sends, and remaining persistent files in an encrypted local restic repository. The existing capture and original-target round trip are recorded separately in `docs/evidence/controller-roundtrip.json`.

The script needs the installed project dependencies, the pinned restic binary, and a local PostgreSQL administrator able to create a randomly named database owned by the fixture role. It obtains only connection authentication from an owner-only URL file; it never queries the source database. No raw URL, session cookie, repository password, passphrase, or kit contents should be pasted into a terminal command, chat, evidence file, or issue.

For an operator recovery rather than a synthetic drill, install a fresh controller using the normal installation procedure. Copy the encrypted kit and its separately held passphrase through private channels. Attach the original backup disk, or supply the provider's narrowly scoped credentials. The kit and passphrase must be held outside both VaultRewind and Vaultwarden.

## Reproduce the non-mutating stages

From the project checkout, obtain the synthetic source instance UUID from private fixture metadata. Pass only that public UUID and a new private runtime directory to the script:

```sh
.venv/bin/python scripts/prove_controller_loss.py \
  --instance <synthetic-instance-uuid> \
  --run-dir .runtime/controller-loss-<unique-run>
```

The defaults refer to the loopback fixture API and its private session and PostgreSQL authentication files under `.runtime/controller/`. Override their *file paths*, rather than passing their contents, using `--source-session-file` and `--connection-auth-file`. `--snapshot` can select an exact complete logical snapshot UUID. Every run directory must be new. It contains generated credentials, the independently encrypted kit, fresh PostgreSQL connection information, and plaintext restored synthetic data; keep its directory mode 0700 and secret files mode 0600.

The script performs these stages:

1. Read a complete snapshot's sanitized metadata through the authenticated source API. Generate a private kit passphrase, enqueue `POST /api/v1/recovery-kits/export`, await the actual worker, and download the encrypted artifact through the authenticated API.
2. Start a separate fresh process with original controller, PostgreSQL, restic and rclone environment settings removed. Block file reads under the old private controller directory. The process receives the encrypted kit, private passphrase file, selected snapshot identity, and new database/key/bootstrap files. It has no original master-key input and never opens the original database.
3. Invoke the shipped offline CLI entrypoint for `discover`, `restore`, and `plan`. Discovery must verify the selected manifest. Restore must verify the complete inventory and SQLite integrity; the deployment plan must verify the descriptor fingerprint and saved image archive hash. Nothing is started or overwritten on a source/target host.
4. Run Alembic migrations against the separate randomly named PostgreSQL database. Start an actual loopback HTTP API using a newly generated master key, bootstrap secret, and password. Create the new owner through `POST /api/v1/setup`.
5. Submit the kit and passphrase in an authenticated request body to `POST /api/v1/recovery/import-plans`. The real worker claims the PostgreSQL queue, discovers the repositories, verifies historical manifests, and stores private import materials encrypted with the fresh key. Inspect `GET /api/v1/recovery/import-plans/{job_id}` and confirm protected mode, no automatic deletion, no conflicts/errors, and the expected snapshot UUID/hash.
6. Submit the reviewed `plan_hash` and an `Idempotency-Key` to `POST /api/v1/recovery/import-plans/{job_id}/apply`. Await the actual apply worker. Read back the snapshot/instance through the API and inspect only the fresh database to confirm historical UUIDs, capture time, image ID, manifest hash, repository and restic snapshot identity, imported repository state, and review holds. The placeholder has no host, schedules are disabled, retention is Keep forever, and a hypothetical one-day retention preview yields zero deletion candidates.

The API subprocess is stopped at the end of this stage. The new database and private runtime directory are retained for diagnosis or the coordinated application stage. No fixture source database is dropped. To clean up a completed drill, shut down every process using its randomly named `vr_loss_…` database, verify that name against the private run metadata, and remove only that disposable database and that run's private files. Never drop `vaultrewind_fixture` or the Compose database. Retain sanitized evidence and any recovery kit required for subsequent work.

## Complete application recovery through the helper

This stage requires an explicitly coordinated maintenance slot and a prepared disposable target. Do not run two controllers against the same physical instance at the same time. Prefer an empty alternate target so the running original source remains unchanged.

The target needs Linux, Docker, the supported systemd recovery facility, a verified SSH host key, scoped helper credentials, an approved empty data path, enough staging space, and a target recovery profile defining its URL/network/ports. Prepare and activate it through the application's administrative enrollment flow. Keep all private connection material in owner-only files; do not copy the old controller master key or its database into the fresh installation.

The synthetic harness can reopen its existing independent controller and register/read-discover a separately approved target. The private descriptor contains `host_create`, `remote_instance_id`, `name`, `container_id`, and the complete approved installed `policy`. It is not copied into public evidence. Preparation is repeatable:

```sh
.venv/bin/python scripts/prove_controller_loss.py \
  --run-dir .runtime/controller-loss-<existing-run> \
  --application-target-private-file .runtime/vm/controller-loss-target-fourth.json
```

That command stops after read-only administrative discovery. Once the fixture owner has reserved the host and confirmed that the final reviewed helper/watchdog bundle is ready, repeat it with `--execute-application-restore`. This explicit phase applies the reviewed matching helper policy through the actual activation-plan/activate API, discovers and enrolls only the descriptor's recovery target, disables its unattended backup schedule, and restores the exact previously imported snapshot with `start_on_completion: true`. The original imported source remains hostless and protected. Before downtime, actual discovery must report `restore_ready: true`. Completion requires both public proof flags from the worker/API and helper, followed by independent content and HTTP readback.

Each target has its own private checkpoint bound to its UUID and the immutable selected snapshot. Repeating a descriptor resumes its saved activation/restore job rather than blindly submitting another job after failure. A different target requires its own explicit authorization and private descriptor; the harness retains the previous sanitized attempt in `application_attempts` and creates a separate UUID-named checkpoint. It never reuses an earlier target's restore job or changes its active generation. The original third-target failure remains recorded when the separately authorized fourth-target attempt runs.

The final readback checks the helper's durable restore journal and current discovery/preflight, then runs a fixed read-only inspection over the descriptor's pinned administrative SSH connection. It verifies the target's recorded image, instance/operation labels, target URL, SQLite integrity, selected synthetic table counts, hashes of captured non-database regular files, and HTTP `/alive` plus `/api/config` readiness on the target's configured port. It reports counts and booleans without returning database rows, environment values, or filenames. No authenticated user login is claimed.

For the original historical identity, run read-only verified discovery with its existing remote instance UUID. `POST /api/v1/instances` can bind the imported hostless placeholder to that verified host/UUID. Check that the existing snapshot/repository UUIDs remain unchanged and its disabled schedules, Keep forever retention, and import holds survive binding. An alternate target receives a separate instance UUID and must prove it is empty. Enrolling or activating a helper changes host state and therefore needs the fixture owner's coordination.

Select the exact imported snapshot, request its restore plan, review target-specific substitutions and preconditions, then execute its one-use confirmation token. The helper must verify restored bytes, load the recorded image, validate the candidate without public ports/outbound access, journal its activation decision, activate the target, and report final health. Replacing an existing target also requires the durable encrypted pinned safety snapshot and preserved old generation. Do not bypass these steps by extracting files into live paths or manually launching the captured container.

Record job IDs, preserved identities/hash, candidate validation, activation outcome, image identity and structural/content checks in the application stage of the evidence. Compare the restored synthetic application to the selected capture, including expected database records and persistent file hashes. Show that post-capture changes are absent when applicable. Report authenticated synthetic login separately; structural startup alone does not prove login, decryption, or synchronization.

Until that coordinated stage has passed, retain `overall: partial` and the actual application-stage state (`not_run`, `prepared`, `running`, or a failure/attention state) in the evidence. Keep unsuccessful prior targets as separate historical attempts. Passing the earlier original-target round trip cannot substitute for this new-controller application restore.

## Automated regression checks

```sh
.venv/bin/pytest -q tests/unit/test_server_import_lifecycle.py tests/unit/test_server_import_binding.py
.venv/bin/ruff check scripts/prove_controller_loss.py tests/unit/test_server_import_lifecycle.py
```

The lifecycle tests use real encrypted restic storage and the actual API/worker implementation with an isolated relational catalog. They cover review-before-apply, wrong-passphrase rejection without catalog creation, plan-hash binding, idempotent repeated apply, fresh-key secret storage, historical identity preservation, and protection/retention behavior. Their small core fixture is explicitly not a saved runnable Docker image; the separate drill uses the real captured application.

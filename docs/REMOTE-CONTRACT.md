# Remote implementation handoff

## CURRENT handoff: final combined bundle and idle VM

Final bundle at `helper/.final-bundle`, SHA-256
`49204778e71115c4a4b553f6bd96e156b8ee337a176b0076ba8016de066acbc5`.
It includes independent watchdog lifetime/retries and boot watchdog resumption,
detached curl probes, the new read-only preflight accounting fields, and ROOT's
current allowlisted core error serializer. Zip entries were byte-compared against
current core/errors.py and remote/docker.py/recovery.py/helper.py. Controller-only
SSHRemote remains in controller source (intentionally not vendored into the root
helper zipapp); ROOT's safe-detail preservation edit was left intact.

ROOT can copy/build this combined bundle into its runtime bundle location and
perform the normal reviewed API activation for native and fresh AC30 workflows.
No new files/units/verbs changed the installer or provisioning artifact contract.
The VM is idle on the daemon-tested bundle `3cf9bb4b401f0a2bb2f2f76663f0487e490019b25da7a3dbfdd27493be4c011d`;
accounting/serializer-only additions in the final bundle await ROOT's coordinated
activation. Zero armed journals, Docker active at final verification, original
four-entry policy restored, boot unchanged. No further VM action is running here.

Preflight fields added for the remote-maintenance agent:
`source_staging_bytes` = sum under operations/; `image_cache_bytes` = sum under
images/; `staging_quota_bytes` = root-policy max_staging_bytes (default 100 GiB).
`staging_bytes` remains source_staging_bytes + image_cache_bytes. No automatic
cache eviction or new verb. Existing capture/preflight test checks positive
components, total equality, and a nondefault quota. After ROOT's core/SSH updates,
84 focused health/SSH/lifecycle/recovery tests passed in 5.60s; owned-source/test
lint passed. New peer-owned test_remote_maintenance.py was left untouched.

Remote/helper work is implemented. Ownership stayed within remote modules,
helper bundle/fixtures, remote tests, and these integration/evidence documents.
ROOT still owns server/adapters.py and the API/worker workflow. Core synchronous
reexports are used as documented; no core changes are requested.

## Stable controller contract

- `SSHRemote.request(verb, instance_id, operation_id, fencing_token, payload=None)`.
- `export(instance_id, operation_id, fencing_token, target:Path, payload=None)`
  writes a bounded, checksum-verified TAR FILE. Then call core `safe_extract` and
  `verify_snapshot`. The export result contains archive `bytes` and `sha256`.
- `upload_restore(instance_id, operation_id, fencing_token, archive:Path,
  payload=None)` streams the archive, adds its size/hash, and invokes stage_restore.
- Capture payload: `snapshot_uuid`, `controller_time` (UTC ISO), optionally
  `expected_fingerprint`. Staging payload: `manifest_hash`, `expected_fingerprint`,
  `controller_time`, optional boolean `start_on_completion` (default false).
- Capture status exposes `snapshot_uuid`, `manifest_hash`, `bytes`, `phase`, and
  source outcome. Optional `payload.idempotency_key` overrides the adapter's stable
  operation/verb/phase-or-kind key. Retry identical payloads after reconciliation.
- Commit phases: `prepare_safety`, `switch_validate`, `activate`. Safety preparation
  returns `safety_snapshot_uuid` and `safety_manifest_hash`, or `empty_target=true`.
  Export with `{"kind":"safety"}`, durably commit/read back the encrypted local
  safety copy and pin it before acknowledgment. `switch_validate.safety_ack` needs
  exact `snapshot_uuid`, `manifest_hash`, `restic_snapshot_id`, `repository_id`,
  and `durable`, `encrypted`, `pinned`, `stored_copy_verified` all true. The helper
  fsyncs this acknowledgment; the controller remains the durability authority.
- Pin AsyncSSH 2.24.1 and PyYAML 6.0.3. Exact allowed image content IDs belong in
  root-owned policy. No caller paths, Docker flags, or shell fragments are accepted.

## Required runner adapter cleanup change

After successful rollback, use:

```python
await remote.request("cleanup", instance_id, operation_id, fencing_token,
                     {"kind": "discard_candidate"})
```

This disposes safely recovered, never-public restore/test candidates. It checks
stopped/no-public/no-restart candidate ownership, original restoration, exact new
generation identities and volume provenance, then deletes candidate containers,
new bind generations, owned named/anonymous volumes and operation staging.
The fsynced per-resource plan supports idempotent repeats and three bounded
attempts per transient failure. Exhaustion returns retryable
`CANDIDATE_CLEANUP_INCOMPLETE`; unsafe resources are preserved. Success requires
`candidate_cleanup_outcome="complete"`, `candidate_cleanup_remaining=0`;
`discarded_candidate_bytes` reports logical candidate bytes. Staging-only cleanup
is not proof of runner disposal. Activated rollback generations still use
`kind=generations` with the existing safety/grace protections.

## Completed safety fixes

- systemd verification queries a concrete inactive watchdog instance, not the bare
  template; the installed read-only verification and regression test passed.
- `/alive` plus a still-running container accepts Docker `starting`, never
  `unhealthy`. Original healthchecks remain unchanged. Candidate SQLite/schema and
  attachment checks are additional evidence, not user login/decryption claims.
- Empty/truncated replies, failed exits and request/stream deadlines return
  retryable `REMOTE_OUTCOME_UNCERTAIN`/`SSH_TRANSPORT_FAILED`. Reconcile status before
  retrying mutation. Complete structured policy errors keep their classification.
- Discovery rejects canonical parent/child overlap and physical bind/volume aliases,
  including stopped peers and empty targets. Labels alone grant no exception;
  retained IDs require root-journal provenance, stopped state and restart=no.
- Immutable capture exports release host/resource locks after opening the archive;
  safety exports record their worker before hashing, allowing watchdog fencing.

## Disposable VM API targets READY

Private file: `.runtime/vm/controller-enrollment.json`, mode **0600**. Never print,
log or commit it. It contains `host_create` ready for API registration, separate
`operational` and `admin` SSH configs, complete preserved `policy`, `targets`, both
UUIDs, installed bundle hash and actual constrained-SSH preflight results.

- Alternate UUID: `b05f7958-3d3b-48d6-a8f2-8eb900533149`.
- Runner UUID: `7902cb54-9b17-4e59-ace0-143236c03c87`.
- Endpoint `127.0.0.1:22229`, pinned key. `vrwcontroller` has a distinct Ed25519
  key, restricted forced helper command and narrow no-argument sudo. Admin remains
  root via the already authorized VM key.
- Distinct empty `/srv/vrw-api-<kind>-<UUID>/data` roots, container names and internal
  networks. Alternate publishes VM loopback 18100; runner publishes no ports.
  Dedicated `.invalid` DOMAIN overlays, capture/restore budget 1200s, validation
  180s. Exact pinned Vaultwarden 1.37.4 image is cached.
- Both targets passed real SSHRemote preflight with `empty_target=true` and
  `recovery_verified=true`. No restore was run against either target by this agent.
  ROOT owns API registration/activation/discovery/enrollment/jobs. Use
  `is_runner=true` for runner and the target UUID as `remote_instance_id`; the API's
  absent-target `container_id` string can be empty.
- Existing reboot-drill source UUID `2d0aab8f-8422-4296-8046-159b3ffa4bb8` remains
  active/running; original old source remains stopped. All drill recovery journals
  are terminal/disarmed and preserved. Boot ID remains
  `eaa17f94-6d57-4a9d-bc12-d3c512411ce9`. No later reboot/native-controller change.

VM target preparation installed bundle SHA-256
`b7413370aed77b108ce8ef4fe76802e6f47ecd4956f40eead58c7c2aed230873`
from `helper/.api-bundle`. Subsequent running-state/safety-export-owner fixes were
unit-tested in source. Current source is built at `helper/.final-bundle`, SHA-256
`c6c659e260aca4a5e0e7540e9937a662189b4fd2cfd113496a378b8c999f8296`.
ROOT should rebuild its `.runtime/helper-bundle` from current source for API
activation. No surprise guest upgrade was made after handoff; never upgrade an
armed operation. The helper CLI import/`--help` check passed.

## Executed evidence and limits

- Final unit/loopback suite and lint pass; current count/timing is in REMOTE.md.
- Real Docker bind/named-volume full restore: 2 passed in 179.22s (earlier run).
- Real Docker bind/named-volume rollback/disposal with actual anonymous volumes:
  **2 passed in 273.83s**. Verified source preservation, generation/volume/staging
  deletion, byte accounting and repeated cleanup. First trial hit a source-stop
  transport timeout before cleanup; fixture teardown and retry succeeded.
- Real parent bind-alias mount/stopped Docker peer rejection: **1 passed in 20.32s**.
- AC22 real systemd independent watchdog after helper SIGKILL: **1 passed in 97.53s**.
- AC23 production helper/systemd, real SSH/Docker and three actual VM reboots:
  **1 passed in 1825.36s**. Capture-stop recovered original; first old rename rolled
  back with later-original data preserved; post-public-start preserved new writes
  and completed without rollback. Evidence: `docs/evidence/remote-vm.json`, tied to
  its exact earlier bundle hash. No controller recovery call produced outcomes.
  Actual encrypted local restic safety commits/readback passed; pinning was a
  fsynced synthetic ledger, not the API/DB pin workflow.
- Parent separately recorded installed localhost capture/cleanup in
  `docs/evidence/ssh-capture.json`.

Docker-only lifecycle fixtures explicitly substitute systemd and safety-ack
storage. Whole API/worker flows remain ROOT's integration work. No production
access/deployment/publication occurred. Generated helper bundles and synthetic
snapshot staging are git-ignored; ROOT should also exclude `helper/.vm-drill` and
other generated helper dot-directories in its owned Docker build context.

## VM API follow-up in progress

ROOT's first activation-plan job failed with HELPER_ACTIVATION_FAILED. Exact root
admin SSH and the unmodified Provisioner BOOTSTRAP discovery both pass directly
(including pinned AsyncSSH, 6.72s). No fixture privilege/key defect is reproduced
yet; a fresh API activation-plan key is queued by scripts/prove_vm_targets.py.

A THIRD distinct empty target is being added at VM loopback 18102 with a separate
UUID/path/network. It will stay unenrolled in the native controller. After reviewed
VM activation and alternate/runner enrollment, the harness writes the exact private
ROOT-requested descriptor to .runtime/vm/controller-loss-target.json (0600), for
the fresh-controller agent to use only after ROOT's explicit GO. No native service
restart or source backup/restore will be performed by this harness.

VM follow-up correction: new plan `8125dd64-37c7-4634-a4f9-c141fffe10af`
succeeded in 16.62s. Activation `6f9fabed-0649-4541-8427-243c43dc318a` was
running when ROOT restarted its worker; the harness is waiting on that SAME UUID,
not creating another activation. Original failed plan elapsed 44.19s. The exact
root BOOTSTRAP succeeds over pinned AsyncSSH; original causal exception is lost by
BOOTSTRAP's blanket sanitized error. No fixture SSH defect has been reproduced,
and this must not be described as an identified/fixed admin failure. Read-only
installed-state and guest command timing diagnostics are continuing.

### ROOT ACTION: activation restart reconciliation gap reproduced

Activation `6f9fabed-0649-4541-8427-243c43dc318a` installed the exact current
bundle `fbfdbaafe78b3c95798cc975297d18c51ee9af7fe3e29f2fc2ef7757260dae32`
and the four-entry VM policy (old drill + three distinct empty targets). Guest
still has boot `eaa17f94-6d57-4a9d-bc12-d3c512411ce9`, zero armed journals and
unchanged drill phases. After ROOT restarted the worker, that SAME job became
terminal `failed / TARGET_CHANGED` with `result.readiness=ready` already persisted.

Worker.handle_activate checks `host.revision != plan.host_revision` before the
idempotent activate_helper step/reconcile. The first execution commits host ready
and increments revision, then separately commits ctx.update/ctx.finish. A worker
loss between those commits makes its own revision increment look like a conflicting
external change. ROOT owns worker/provisioning; recommended fix: journal the
activation identity with the host update and complete the job in the same fenced
transaction, or explicitly recognize/reconcile this exact already-applied plan
without incrementing the host revision twice. A generic revision bypass is unsafe.
No server file was changed by this agent. No second activation has been queued;
prior job is now terminal, so a NEW reviewed plan can proceed once ROOT coordinates.

ROOT confirmed/fixed the activation restart gap in its worker source by making
terminal success atomic with host/policy revision updates. Existing VM host is
ready at revision 2. This agent did not retry the old activation UUID. A new plan
`fd83ba59-d6f8-455a-9d58-921ba7f3885f` was already queued after the failed job
became terminal, and the harness will complete this ordinary reviewed activation
before operational discovery/enrollment. The reviewed policy includes all three
empty targets plus the preserved drill entry; no additional application mutation.

Original planning-failure investigation: guest SSH journal during
16:22:40–16:24:00 UTC records one accepted root public-key authentication and zero
failed-auth/preauth disconnects. Root fixed-command bootstrap now succeeds with
exit 0 and zero stderr; component timing measured docker info 1.87s, docker ps
0.31s. Original 44.19s failure is not reproducible and its post-login exception
was discarded, so timeout remains an inference, not an identified cause. ROOT can
improve diagnosis with fixed allowlisted bootstrap stage/error codes (e.g. Docker
info/ps/inspect timeout) without exposing raw stderr or configuration. No fixture
credential/permission change is justified by the observed evidence.

THIRD target descriptor is now present at
`.runtime/vm/controller-loss-target.json`, verified mode 0600, with exactly the
requested keys: host_create, remote_instance_id, name, container_id, policy.
Its policy was read back from the actually installed guest policy and matched in
full. Third UUID `3269177e-9c84-4143-abc6-8658e4f0a766`, loopback port 18102,
container name `vrw-api-recovery-3269177e-9c84-4143-abc6-8658e4f0a766`.
Fresh-controller agent must still await ROOT's explicit GO; this agent has not
registered it natively or performed application restore. Fresh reviewed plan
`fd83ba59-d6f8-455a-9d58-921ba7f3885f` succeeded; new normal activation
`72300973-e579-4720-a1c8-71905de02deb` is running. Old failed activation was not retried.

## VM API enrollment COMPLETE — ROOT can proceed

`scripts/prove_vm_targets.py --new-plan-after-terminal-activation` completed
successfully through the real API8098. Reviewed plan
`fd83ba59-d6f8-455a-9d58-921ba7f3885f` and activation
`72300973-e579-4720-a1c8-71905de02deb` succeeded. Operational discover jobs
`165747ff-7805-48b9-a18f-7ee267e2eff3` (alternate) and
`7e5a6bdc-9fac-4e92-8ff8-1f138ff37c86` (runner) succeeded; both instances were
registered natively, ready with absent source state. Runner is_runner=true.

`.runtime/controller/integration.json` was merged with alternate_id/name,
runner_id/name and vm_host_id, preserving existing source/destination fields.
Host UUID `56159034-4928-4b47-9ca8-f88cc4fff507`. Existing alternate and runner
UUIDs above are unchanged. Native browser may now use the alternate and runner.

`.runtime/vm/controller-loss-target.json` is ready in the exact requested shape,
mode 0600. Third UUID `3269177e-9c84-4143-abc6-8658e4f0a766` is NOT registered
in the native controller (API 404 verified); its full policy was verified against
the installed guest. ROOT can pass the descriptor and explicit GO to the fresh
controller agent without sharing the browser's alternate target. Port is 18102.
No source backup/restore, application activation, native restart or journal cleanup
was performed by this harness. All old guest policy entries/journals remain.

Evidence: `docs/evidence/vm-targets.json`. It distinguishes the unreproduced initial
post-login planning failure from the confirmed worker-restart revision gap and
records the eventual successful reviewed activation/discovery/enrollment. The
initial causal exception is unavailable, not silently classified as fixed or as
pagination. ROOT reported its atomic-success worker fix; no server files were
edited here. Fixture/harness lint and Python compilation passed.

## Detached Docker readiness probe READY for ROOT bundle rebuild

Only `remote/docker.py` and focused remote tests changed for this runtime follow-up.
The fixed curl exec now starts with `Detach=True`, `Tty=False`, stdout/stderr
unattached. Existing bounded exec inspection waits for Running=false/ExitCode=0;
container-running recheck and rejection of Docker unhealthy are preserved. No
stop timeout, graceful-stop validation, safety state machine or deployment changes.

Docker transport errors retain DOCKER_UNAVAILABLE and now attach only fixed safe
`VaultRewindError.details` fields: `operation_category` (e.g. exec_start,
exec_inspect, exec_create, containers_stop; unknown routes become docker_request)
and `transport_kind` (timeout/http_protocol/invalid_response/os_error). Raw IDs,
queries, URLs, host paths, environment and exception strings are never included;
exception chaining is suppressed. ROOT subsequently added fixed-allowlist serialization in core.errors, preservation
in SSHRemote.request and worker job-result persistence. Those ROOT edits are
preserved; the combined final bundle includes the current core serializer.

Verification: focused readiness/diagnostic/security tests **60 passed in 0.42s**;
existing lifecycle/SSH tests **52 passed in 5.71s**; lint passed. New real Docker
fixture ran **25 consecutive health probes** against a newly created labelled
Vaultwarden 1.37.4 container with network=none/no public ports, then gracefully
stopped and removed it and verified data-directory deletion: **1 passed in 29.78s**.
No VM access/reboot, native/API jobs, source mutations or worker restart occurred.
ROOT can rebuild and activate its bundle after coordinating active jobs.

The attached-stream race remains an inference from ROOT's event sequence, not a
proven cause of the earlier DOCKER_UNAVAILABLE. The successful detached-probe test
is evidence of this replacement path; it does not retrospectively identify that
failure. New safe operation categories support diagnosing any recurrence.

## Review02 P1 daemon lifetime fix in progress — VM reserved for test

The watchdog no longer Requires Docker (ordering remains After only), and the
recovery loop no longer exits after a failed attempt while its journal is armed.
It retries with 2/4/8/16/30-second capped delays without extending the original
deadline. Boot reconciliation starts every armed per-operation watchdog before
attempting recovery; boot unit Wants Docker rather than Requires it. Unit restart
rate limiting is disabled so prolonged infrastructure outages cannot exhaust the
restart allowance. No new unit/trigger/protocol file is introduced; the existing
bundle-unit digest mechanism covers the changed two unit files. Installer/server
expected-file sets remain unchanged. Preflight rejects old watchdog units with
Docker Requires/Requisite/BindsTo/PartOf dependencies.

The authorized real test is running ONLY on SSH-22229: new separately labelled
synthetic source, production helper/units, test-only SIGKILL after graceful source
stop, then guest docker.service AND docker.socket stop (socket stop prevents
socket activation), hold beyond deadline, guest Docker start, independent recovery.
No controller/host Docker commands, reboot, native API mutation or old-journal
modification are part of this test. AC30 agent must remain paused until final VM
idle/bundle hash is reported here. Initial unit regression run passed 80 tests;
real daemon proof is not yet claimed.

## Review02 daemon-stop proof PASSED; VM idle

`VAULTREWIND_REMOTE_VM_DOCKER_TEST=1 .venv/bin/pytest tests/unit/test_remote_vm_docker.py -x -q`
passed: **1 passed in 581.43s**. The SAME production watchdog PID (5626, zero
restarts) survived stopping guest docker.service and docker.socket. At 9.4s beyond
the original deadline it remained active with armed journal/source_recovery_failed.
After guest Docker started, it independently restored the originally running
source, returned failed_safe/source_service_outcome=running and disarmed. No
controller status/recover produced that outcome. No reboot occurred.

Exact original journal hashes, old container running/stopped states and restart
policies, and the old synthetic post-activation sentinels were verified unchanged.
Own source/container/network/data/staging were removed; the new disarmed test
journal is retained. Original four-entry policy restored. Final VM has zero armed
journals and unchanged boot eaa17f94-6d57-4a9d-bc12-d3c512411ce9. Docker was active
at final installer verification. Test evidence: docs/evidence/remote-vm-docker.json.
Only this explicitly authorized VM's Docker daemon/socket were stopped/started;
controller/native Docker and native jobs were untouched.

VM's installed and daemon-tested bundle SHA-256:
`3cf9bb4b401f0a2bb2f2f76663f0487e490019b25da7a3dbfdd27493be4c011d`,
retained at helper/.daemon-bundle. Subsequent accounting-only additions are being
built into helper/.final-bundle for ROOT's normal API activation; no further VM
mutation/reboot is planned. Both units keep their existing names, and bundle file
sets/protocol checksum contract remain unchanged. ROOT can resume coordinated
AC30 activation after selecting the final combined bundle below.

All remote unit/loopback tests after watchdog changes: **120 passed, 9 opt-in
skipped in 6.66s**; lint passed. Boot-resume ordering, indefinite outage retries,
bounded duplicate journal history and interrupted disarm have regressions.
New boot behavior has unit coverage; this run proves daemon stop/start, not reboot.

## Public readiness contract (implementation in progress, 2026-10-25)

`preflight` still calls `SystemdRecovery.verify()` FIRST and propagates
WATCHDOG_UNAVAILABLE and all other existing base preflight failures. Added safe
fields on a successful result: `restore_ready: bool`, `restore_error_code: str|null`,
`current_public_ports_ready: bool|null`, `current_public_error_code: str|null`.
`discover` returns the same fields; `restore_enabled` is false when desired
profile is unready. Null current readiness means absent/stopped; true only proves
actual Docker port allocation (HTTP endpoint is tested at activation).

Desired network is recovery_profile.network, falling back to the current
container network, or the single allowed network for an empty target. Desired
ports are recovery_profile.port_bindings, falling back to policy.port_bindings.
Source discovery/capture accepts an approved old internal network even when its
published ports are broken. Current actual port-map failure is reported separately
and does not block capture or a corrected desired-profile restore.

Known desired-profile errors: PUBLIC_NETWORK_UNPUBLISHABLE (internal bridge or
non-NAT gateway with expected ports), PUBLIC_BIND_UNSUPPORTED (non-loopback,
non-wildcard binding cannot be locally probed safely). Stage_restore raises the
specific code before transfer/downtime; prepare_safety revalidates before arming.
Invalid desired settings otherwise retain POLICY_INVALID, DEPLOYMENT_UNSAFE,
TARGET_PROFILE_REQUIRED or DEPENDENCY_UNREADY. Infrastructure/transport errors
must remain fatal, not be downgraded to readiness warnings. Provisioner can keep
a host ready after successful base preflight and attach the explicit known
per-instance public error without changing/repairing preserved profiles.

Postactivation errors PUBLIC_PORTS_UNAVAILABLE and PUBLIC_ENDPOINT_UNAVAILABLE
leave needs_attention with activation_started=true. No rollback/recreation.
Actual Docker NetworkSettings.Ports must match approved addresses/ports; fixed
loopback /alive (80/tcp) or TCP (3012/tcp) must pass. No DOMAIN URL/DNS/redirect
probe. Success adds public_ports_verified/public_endpoint_verified booleans.
Legacy completed internal-only journal status rechecks public proof read-only;
failure downgrades needs_attention, without restart or rearming. Superseded
legacy result with no proof reports PUBLIC_READINESS_UNVERIFIED.

Current VM third remains running and untouched. Read-only guest Engine version
is 26.1.5+dfsg1, internal network true and actual Ports {}. Native old fixture
network also Internal=true. This is not established as a Docker 28/29 regression.
Fourth will be a fresh empty non-internal network/loopback18103 target; no restore
or old journal mutation. No guest app test/daemon/reboot mutation this round.

Fourth EMPTY target prepared (no helper activation, no restore, installed policy
unchanged): private `.runtime/vm/controller-loss-target-fourth.json` mode0600,
remote_instance_id `02b09a69-7c5f-4695-85f5-8514364ca6f5`, container/network
`vrw-api-recovery4-02b09a69-7c5f-4695-85f5-8514364ca6f5`, loopback18103,
network Internal=false, clean separate /srv/.../data. Descriptor full policy has
five entries and retains all four installed profiles unchanged. ROOT/fresh agent
can use its full host_create/policy for normal reviewed activation AFTER final
bundle is ready. The third active container/network/data were not modified.
Guest app test mutations are not authorized this round; no VM app test was run.

## Public readiness implementation READY

Final narrow readiness behavior: ONLY PUBLIC_NETWORK_UNPUBLISHABLE and
PUBLIC_BIND_UNSUPPORTED become restore_ready=false. Other policy/descriptor,
watchdog and transport errors propagate. No server changes were made here.

Full remote suite: 152 passed,10 opt-in skipped (6.55s). Actual isolated native
Docker regression: 1 passed155.65s. Docker26.1.5+dfsg1 reproduced internal=true
=>Ports={}+PUBLIC_PORTS_UNAVAILABLE; non-internal NAT => actual allocation and
host /alive passed. TEST-ONLY postactivation probe failure preserved the live
generation/new write; recovery completed only after real public proof. Own
containers/networks/data cleaned. No VM app or native source was changed.

READY combined bundle: helper/.final-bundle/helper.pyz SHA-256
`1ba90b4a54c4d2e460fe7772877025eec55aeb5221e3446d9ed8ddf8be46bf33`.
Includes independent watchdog, detached health exec, source/image staging
accounting, public readiness, and current ROOT core error serialization. Unit
names, expected installation files and checksum contract unchanged. ROOT retains
SSH safe-details changes in controller source (ssh.py intentionally excluded from
helper bundle). Bundle built but NOT installed by this sub-agent on native or VM.

Fourth descriptor `.runtime/vm/controller-loss-target-fourth.json` mode0600 is
ready for fresh agent reviewed activation with this bundle. No fourth restore
has run. Existing third active data/container/network and installed policy remain
untouched. Native source upgrade/overlay/confirmed restore remain ROOT-owned.

## Review03 corrections: source fixed, local proof running

Running restore now requires at least one approved HTTP80 host binding. New
PUBLIC_ENDPOINT_REQUIRED is a known readiness=false code for a currently running
source, and stage_restore also checks start_on_completion=true before downtime.
Absent/stopped targets with start_on_completion=false retain data-only staging
and isolated runner validation. Docker.public_health never returns public success
for an empty port map. Activation and post-boundary recovery enforce this again.

Recovery reapplies AND inspects the recorded restart policy before starting and
completing a running final container. Data-only recovery sets/verifies restart=no.
A silently ineffective restart update remains needs_attention.

Only DOMAIN is supported in explicit recovery_profile.environment substitutions;
unknown keys/malformed URL fail TARGET_OVERLAY_UNSUPPORTED without values in
errors. The approved normalized DOMAIN is applied to private new-generation
config.json, preserving its mode/owner/xattrs. Original capture/archive, verified
incoming staging and live old generation are unchanged. TARGET_CONFIG_MISMATCH
blocks activation if the new config no longer matches. This honors documented
Vaultwarden config.json precedence; real /api/config verification is in progress.

Generation steps now use journal.original.mounts (actual current active mounts),
record old volume metadata+inode provenance, and cleanup verifies/deletes only
that previous volume after grace. Stopped isolated candidate containers are
removed after verified public success or stopped data-only final creation,
without deleting active volumes/data. Recovery repeats this idempotently.

157 focused remote tests passed (6.70s), lint passed. Candidate bundle currently
helper/.final-bundle/helper.pyz SHA256
9955c8646d521b7bbec50db93b9416b327265b33d3c366d7004dc2b5560c5883.
The old 1ba bundle is preserved at helper/.frozen-1ba, and
.runtime/helper-bundle remains EXACTLY 1ba90b4a54c4d2e460fe7772877025eec55aeb5221e3446d9ed8ddf8be46bf33.
No install/activation, VM call, native source or primary fixture mutation.
Standalone local proof: tests/unit/test_remote_stopped_offline.py --run; tests the
built zipapp and real Docker/restic, with only systemd orchestration substituted
and a private fsynced controller pin/ack record. Evidence will be
 docs/evidence/stopped-offline.json. Includes AC03/06/10/11 and real free-space
reserve failure before mutation (AC26); no shared disk fill.

Offline-only network recommendation (not applied here): keep old source networks
in allowed_networks and set the approved recovery_profile.network to ROOT's new
vrw-native-alternate-public (non-internal NAT bridge), preserving source UUID,
port bindings and explicit DOMAIN. Running alternate profiles need HTTP80 host
bindings. Empty runners remain data-only with start_on_completion=false; they
must not activate a running application without a separately approved endpoint.

## Review03 and local acceptance proof READY (final)

Final candidate helper/.final-bundle/helper.pyz SHA256:
`8e7775f757002f07f67d6d3616f5288186f75291c352ab19409f44e09a51bf0d`.
Byte-verified against current core/remote source. ROOT may now copy/review this
candidate through the normal activation workflow. NO activation performed here;
.runtime/helper-bundle stays frozen at1ba90b4a54c4d2e460fe7772877025eec55aeb5221e3446d9ed8ddf8be46bf33.

Final unit/loopback suite158 passed,10 opt-in skipped (6.77s), lint passed.
Real public preservation regression1 passed45.07s using current source.
Standalone stopped/offline proof PASSED408.39s; evidence
`docs/evidence/stopped-offline.json`, repeat with
`.venv/bin/python -I tests/unit/test_remote_stopped_offline.py --run`.

Proved: AC03 live root-owned0600 data/config unchanged by capture; AC06 manually
created container/no Compose restored from captured normalized deployment; AC10
capture source stayed stopped and original-target data-only restore stayed
stopped/restart=no; AC11 unique recorded image REMOVED from Docker then loaded
from actual saved archive and used by restored container, zero pull attempts;
foreign architecture rejected while fixture source remained running with same
StartedAt, zero Docker mutations/arms before rejection. AC26 actual filesystem
reserve > measured free space rejected before source mutation, same State,
StartedAt and full data hash; shared disk was not filled.

Real restic safety export, encrypted commit and full verified readback preceded
fsynced fixture pin/ack and switching. Real /api/config reported target DOMAIN
from restored config.json while captured original config remained unchanged.
Only systemd orchestration and worker database pin/ack are substituted; this is
not full worker/systemd evidence. Shared base image layers remain cached; the
unique recorded image identity was actually absent before restore.

The real standalone proof executed bundle9955c8646d521b7bbec50db93b9416b327265b33d3c366d7004dc2b5560c5883
(retained at helper/.review03-tested). Final8e7775 adds ONLY the independently
unit-tested legacy zero-endpoint receipt guard afterward; evidence records both
hashes accurately. All created containers/networks/unique image/private data and
temporary restic repository were cleaned. No VM calls, primary source changes,
shared Docker lifecycle changes or installations occurred.

## Historical-status fix: provisional ROOT upgrade wiring

New source exposes `Helper.reconcile_historical_status(operation_id, apply=False)`.
Default is a locked, read-only dry-run returning eligible, journal_sha256,
superseded_by and changed=false. It never starts/stops/execs/renames containers or
rewrites the active registry. Optional `apply=True, expected_sha256=<reviewed raw
journal SHA256>` performs only the narrowly validated journal transition. Do not
hand-edit phases or weaken the global fence.

Preferred product upgrade path for ROOT's fixed administrative BOOTSTRAP:
1. Verify the proposed controller-owned helper.pyz SHA256, stage it privately in
   a temporary directory, and run a fixed `python3 -I` validator importing that
   zipapp and installed Policy.load(). The installed8e/71 helper cannot expose
   this new predicate; do not duplicate a weaker approximation in provisioning.
2. For EVERY pending journal call the candidate's dry-run method. Admission is
   allowed only if ALL are eligible and all reported journal hashes still match.
   Include candidate checksum, operation IDs, hashes and successor IDs in the
   reviewed activation plan as an explicit historical-status upgrade exception.
3. Recheck the pending set and predicate immediately before install; hold the
   host flock across that recheck/install boundary so a new operation cannot
   enter between proof and installation. Preserve rejection of any armed,
   current-uncertain, unrelated pending or changed journal. No journal repairs
   occur during this upgrade admission.
4. After reviewed installation, normal operational status for each eligible old
   UUID uses the new narrow locked repair before live fencing. Or explicitly use
   the hash-checked admin method. Keep error/warning and original history.

Predicate: old restore needs_attention with EXACT PUBLIC_READINESS_UNVERIFIED,
watchdog=false, no live owner, prior complete history after activation, no prior
public success proof. Active registry must point to a DIFFERENT same-instance
restore created AFTER that original completion, terminal/disarmed/no live owner,
with ordered candidate_validated/activation_started/terminal history and actual
candidate HTTP+SQLite evidence. Its container/image/ownership labels/name/mounts,
physical generation identities and active-registry descriptor hash must match.
Running successor requires recorded nonzero public proof and current actual
Engine port/approved loopback HTTP proof; stopped successor must be intentionally
stopped, restart=no, with no actual published ports. Restart policy is checked.
The active registry and newer journal are reread unchanged before admitting.

This is not an install-script change; installer itself already rejects armed
journals. ROOT owns provisioning admission/review and any fixture application.
No shared journal/host/VM access has been performed here. Source tests and final
candidate checksum follow after verification.

ROOT wiring clarification (avoids nested flock): candidate source now also exposes
`Helper.historical_status_evidence_locked(operation_id)`, same dry-run result as
`reconcile_historical_status(op)`. The fixed administrator program must call it
inside `with Locks(service.root, []):`, then keep that lock through reviewed
installer subprocess completion. Do NOT call the locking reconcile wrapper under
an outer Locks context. Build the service from INSTALLED policy for proof, not the
proposed replacement policy. Under that lock, enumerate the exact pending set,
prove every entry, compare operation IDs/raw journal hashes/successor IDs to the
reviewed plan, and abort on any difference or ineligible record. Existing terminal
records with watchdog_armed=true must still block (the installer also checks).
Only the administrator's fixed bootstrap gets this method; no protocol verb,
caller shell fragment, automatic upgrade or general fence relaxation is added.
The reviewed candidate checksum must anchor this validator before it is executed.

Historical-status candidate READY for ROOT review:
- helper/.final-bundle/helper.pyz SHA256:
  cbf84b999eab462a6ad08b86ef06c631c148e796d242459f227c79df2a0a0093
- Only remote/helper.py and remote/journal.py differ inside the bundle from ROOT71.
  Docker.stop reconciliation and core/errors.py are byte-identical to ROOT71.
- Remote suite: 254 passed, 11 opt-in skipped, 28.56s. Historical regressions:
  70 passed, 10.62s. Ruff passed. Unit Docker/systemd doubles are explicit.
- .runtime/helper-bundle remains frozen8e7775; no install, SSH/VM/native state,
  shared journal, policy or container calls/mutations were performed.
- Exact admin APIs and fixed-bootstrap locking procedure are above and in
  docs/REMOTE.md. Product admission needs ROOT provisioning implementation; the
  installer is unchanged and will still reject any armed journal.
- Keep installed instance entries in proposed policy; run predicate against the
  INSTALLED policy. Never permit a pending record solely from its error string.
Packaged verification also passed: all 70 historical cases executed using imports
from the built cbf84b999e zipapp in 10.61s. Final bundle/source member comparison
and unchanged runtime8e checksum verified.

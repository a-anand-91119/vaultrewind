# VaultRewind SSH, Docker and recovery helper

The controller uses AsyncSSH and one fixed command:

```
sudo -n -- /usr/local/libexec/vaultrewind-helper
```

The helper is privileged, root-owned, policy-scoped software on each enrolled
Linux Docker host. It is not a network listener. Read-only discovery does not
install packages, change policy, start containers, write a snapshot or arm a
watchdog. The read-only helper/policy must already be provisioned; provisioning
and enabling backup/restore operations are explicit administrative enrollment
steps. No production access is authorized by the development fixtures.

## Installation and host changes

Use Python 3.13+, Docker Engine API v1.41 or later, local Linux filesystems with
fsync, rename, numeric ownership and the metadata used by the protected instance,
and a working systemd system manager. The tested Engine is Docker 26.1.5. The
recorded official Vaultwarden Debian image supplies `curl` for the fixed internal
readiness probe. Alpine/custom images lacking that probe are not claimed tested.

The controller dependency is AsyncSSH 2.24.1. The build uses PyYAML 6.0.3 to
inventory original Compose dependencies. Exact helper build dependencies are in
[requirements.lock](../helper/requirements.lock). The helper bundle vendors the
pure Python YAML parser and the shared core implementation, so normal helper
operation does not download dependencies. Reference semantics were checked against
[AsyncSSH's documentation](https://asyncssh.readthedocs.io/en/latest/), the
[Docker Engine API](https://docs.docker.com/reference/api/engine/version/v1.41/),
and [systemd service documentation](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html).

Build a bundle on the controller from reviewed source:

```bash
.venv/bin/python helper/build_bundle.py /secure/build/vaultrewind-helper
sha256sum /secure/build/vaultrewind-helper/helper.pyz
```

Inspect [policy.example.json](../helper/policy.example.json), replace every
synthetic placeholder with the explicitly enrolled host identity and approved
instance mappings, and review the complete file. An administrator then runs the
bundle's installer locally on the prepared host:

```bash
sudo python3 /secure/build/vaultrewind-helper/install.py \
  --policy /secure/enrollment/helper-policy.json \
  --ssh-user vaultrewind \
  --bundle-sha256 REVIEWED_HELPER_PYZ_SHA256
```

The SHA-256 argument is the reviewed build identity, not a value fetched by a
backup job. The installer verifies the bundle and stages the verified executable
before importing its code. It refuses upgrades/policy replacement while a journal
has an armed watchdog. It creates:

- `/opt/vaultrewind-helper/<bundle-sha256>/helper.pyz`, immutable versioned code;
- `/usr/local/libexec/vaultrewind-helper`, a root-owned wrapper using `python3 -I`;
- `/etc/vaultrewind/helper-policy.json`, root-owned mode 0600;
- `/var/lib/vaultrewind-helper`, root-owned mode 0700;
- the watchdog template and enabled boot reconciler in `/etc/systemd/system`;
- root-owned unit drop-ins allowing writes only to enrolled bind generation parents
  in addition to helper state, `/run`, and local Docker volume storage;
- `/etc/sudoers.d/vaultrewind-helper`, validated by `visudo`.

The sudo rule permits the helper **without arguments**. Administrative watchdog
and boot-reconcile arguments are usable by root/systemd, not by the SSH account.
Give the SSH account no Docker group membership or broader sudo access. Restrict
its authorized key, for example with `restrict,command="sudo -n --
/usr/local/libexec/vaultrewind-helper"`; no source secrets belong in the key
comment. Agent forwarding, user SSH config, password fallback and PTY allocation
are not used by the controller. The verified OpenSSH host public key is supplied
explicitly to AsyncSSH; a mismatch blocks the operation.

Removing the helper is an explicit local administrator action. First reconcile
all armed/nonterminal journals and preserve or export required safety/rollback
material. Disable the boot reconciler, remove the narrow sudo rule and units, then
remove versioned executables. Never delete helper state as an uninstall shortcut
while an operation is ambiguous.

## Enrollment and supported recovery boundary

The root-owned policy binds a canonical instance UUID to a full immutable Docker
container ID, host machine ID, daemon ID, allowed verbs, approved image IDs,
mount mappings, files, target ports/network, recovery substitutions and budgets.
Paths are absolute, canonical and free of symlink components. Policy and state
ancestors must be root-owned and not writable by another account. State is 0700.
Bind generation parents must be administrator controlled and on the same
filesystem as the live path; a bind root which is itself a mountpoint is blocked.

Every persistent mount is compared with Docker's actual mount list, including
type and access mode. `/data` maps to canonical snapshot `data/`; other mounts map
to `deployment/mounts/<id>`. Single files and directories are supported as additional
binds. Volumes must use the plain local Docker driver, local scope and no driver
options. New restored volumes are created through Docker; their internal storage
directories are never renamed.

Capture includes unknown files, dotfiles, empty directories, mode-0600 content,
UID/GID, permissions, times, internal relative links, within-mount hard links and
supported xattrs/ACLs. Copies validate opened file identities and retain the source
metadata. No live chmod workaround is used. Symlink escapes, cross-boundary hard
links, devices/FIFOs/sockets, nested filesystems, executable capabilities and
setuid/setgid metadata fail closed. Unsupported metadata is an error, not a
warning or successful partial capture.

Additional enrolled deployment files are stored under `deployment/files/`.
Original Compose includes, env files, configs and secrets must all be enrolled;
`.env` next to a captured project is required when present. Compose aliases and
interpolated dependency filenames need a flattened/resolved enrollment definition.
Captured Compose is evidence only and is never executed. Additional proxy or
certificate files are captured as declared external prerequisites; the helper
does not reconfigure unrelated reverse proxies or identity providers.

The initial supported profile intentionally rejects configurations it cannot
faithfully recreate: external databases, custom database/persistent paths, overlapping
container mount targets, nonlocal volumes, privileged/device containers, added
capabilities, host/shared namespaces, multiple networks, static network addressing,
custom aliases, unsupported resource/security settings, custom entrypoint/command
overrides, custom hostnames and unenrolled dependencies. Error codes identify the
blocked prerequisite before downtime. New functionality needs an explicit adapter
and matching recovery tests rather than silently dropping a setting.

Enroll exclusive writer/deployment ownership. Known auto-healer labels and other
containers overlapping protected mounts block discovery, including stopped peers,
parent/child paths and physical bind/volume aliases. Matching labels grant no
exception: retained containers require exact root-journal identities and must
remain stopped with restart disabled. Empty-target discovery applies the same
checks. Root ownership approval is
an operator assertion about host-native writers and external deployment tools;
the helper cannot discover every arbitrary external process. Existing Compose or
auto-healing controllers must honor the ownership transfer. Each historical image
intended for restore must be in the root-owned `allowed_image_ids` list. Unknown
images require an administrative policy review, not a request override.

## Protocol and controller integration

The request is one JSON line of at most 1 MiB. Duplicate fields, non-finite
numbers, unsupported schema/verb/fields, noncanonical UUIDs and invalid fencing
tokens are rejected. Every request has:

```json
{
  "schema_version": 1,
  "instance_id": "11111111-1111-4111-8111-111111111111",
  "operation_id": "22222222-2222-4222-8222-222222222222",
  "idempotency_key": "operation:capture:default",
  "fencing_token": 1,
  "verb": "capture",
  "payload": {
    "snapshot_uuid": "33333333-3333-4333-8333-333333333333",
    "controller_time": "2026-10-25T12:00:00+00:00"
  }
}
```

Normal replies are `{ok:true,result:{...}}` or a sanitized
`{ok:false,error:{code,message,retryable}}`. No subprocess stderr, environment
values or vault file names are emitted to normal job responses.

| Verb | Behavior |
| --- | --- |
| `discover` | Read-only identity, database, mount/dependency and inventory checks. |
| `preflight` | Read-only readiness, recovery-unit, clock skew, space and quota checks. |
| `capture` | Immutable full-instance capture, original-state recovery, normalization and sealing. |
| `export` | Framed immutable `capture` or `safety` tar stream. |
| `stage_restore` | Framed input, snapshot/image verification and complete new generation. |
| `commit_restore` | `prepare_safety`, `switch_validate`, then `activate`. |
| `rollback` | Recover the original only before activation may have begun. |
| `status` | Durable status and recovery of interrupted armed operations. |
| `cancel` | Request cancellation; recovery precedes a terminal outcome. |
| `cleanup` | Staging cleanup, disposal of never-public rolled-back candidates, or retirement of old activated generations after grace. |

The async adapter signatures are in [REMOTE-CONTRACT.md](REMOTE-CONTRACT.md).
`export(..., target)` writes a file, not an extracted directory. The controller then
uses core `safe_extract` and `verify_snapshot`. Both capture and restore staging
require a current `controller_time`; unaccounted clock skew over two minutes fails.
Restore also requires the exact confirmed target fingerprint and manifest hash.
The adapter adds archive size/hash and chooses a stable operation/verb/phase
idempotency key unless an explicit one is provided.

Binary transfer uses an eight-byte `VRW1` magic header, big-endian uint32 length
frames of at most 1 MiB, a zero-length terminator, and a bounded JSON byte-count /
SHA-256 trailer. Both sides enforce byte limits and reject truncation. Tar members
are validated in full before extraction: no traversal, absolute paths, special
files, duplicate entries, link parents, unsafe hardlinks or unexpected top-level
sections. Ownership/xattrs are restored only from the verified manifest within
private staged roots. Image archives are imported only after checksum, config-ID,
platform and path validation; mutable tag reassignment is prohibited.

A request's identity is fsynced before side effects. A key cannot be reused with a
different payload. On an empty/truncated helper reply or an unsuccessful exit after
purported success, the adapter raises retryable `REMOTE_OUTCOME_UNCERTAIN`; SSH
transport loss raises retryable `SSH_TRANSPORT_FAILED`. The controller must ask
`status` and reconcile, not repeat an ambiguous destructive command. Fully formed
helper policy errors retain their actionable code and retryability.

## Capture and durable recovery

Image export/cache preparation occurs before source downtime. The cache records
its immutable image ID, archive hash and byte count. A changed cached archive
blocks capture. Recovery descriptors distinguish registry digest, local image ID
and saved-archive digest.

The helper fsyncs the original container state/restart policy, arms and verifies an
independent systemd watchdog, then disables daemon auto-restart and gracefully
stops the enrolled writer. Exit 137/forced termination invalidates the capture.
All approved files are copied while stopped and the deployment fingerprint/writer
state is checked again. The original state is restored before SQLite normalization,
archive creation or SSH export. A previously stopped source stays stopped.

The fixed internal `/alive` probe plus a running container establishes readiness
while Docker may still report `starting`; `unhealthy` never passes. Candidate
validation additionally performs SQLite schema/integrity and attachment-reference
checks. These checks do not claim user login, decryption or synchronization.

Journals use atomic replace plus file and directory fsync. OS flocks coordinate the
host and individual physical resources. Canonical path, inode, daemon and volume
identities prevent duplicate-registration races; a durable host reservation spans
separate restore calls and blocks overlapping jobs until reconciliation. Fences
are monotonic. The watchdog records boot identity, process start identity, wall
and monotonic deadlines; an expired/cancelled worker is terminated before recovery
acquires its locks. Exports during restore safety downtime also record their owner
so a stalled SSH transfer cannot prevent watchdog recovery indefinitely. Immutable
capture exports hold an open archive descriptor and release host/resource locks
before hashing or streaming, allowing independent recovery during later restores.

The watchdog has only ordering against Docker, so stopping Docker does not stop
recovery. An expired operation keeps retrying while its journal remains armed,
with delays capped at 30 seconds and without extending its original deadline.
Unsuccessful attempts remain visibly failed/pending; only verified recovery
clears the armed flag. Identical failures do not grow journal history indefinitely.
The watchdog has no service start-rate cutoff, and preflight rejects installed
units whose Requires/Requisite/BindsTo/PartOf links tie their lifetime to Docker.

The boot reconciler wants Docker but does not require a successful daemon start.
Before each recovery attempt it restarts that journal's independent watchdog,
without resetting its deadline, so a boot oneshot exit cannot abandon a pending
operation. No extra daemon listener, scheduled task or Docker-start trigger is
installed. The two existing units remain covered by the bundle's pinned digests.
Original containers have restart disabled before stop, preventing daemon restart
from choosing an obsolete generation. Corrupt/ambiguous journals fail closed and
preserve generations. The watchdog and boot reconciler do not depend on the
controller connection or a Python `finally` block.

## Restore transaction

Download, verify, image import and generation materialization happen before target
downtime. Bind generations live under private root-owned sibling directories on
the same filesystem. Named-volume generations use new labeled local volumes.
No archive is extracted over the live data tree.

`prepare_safety` arms the maintenance watchdog, stops the original and creates a
complete safety capture. The controller exports it, commits it to its encrypted
local safety repository, verifies readback and pins it. `switch_validate` requires
an acknowledgment with exact safety UUID/hash, repository/restic identities and
`durable`, `encrypted`, `pinned`, `stored_copy_verified` all true. The acknowledgment
is fsynced before switching. The trusted controller is the durability authority;
these fields alone are not proof that a repository commit happened. A proven empty
alternate target has no old data and skips the safety-content requirement.

Each bind rename has durable intent/evidence. New containers re-resolve mounts.
The candidate uses `NetworkMode=none`, no published ports and restart disabled.
It cannot send SMTP/webhook/push/identity-provider requests. Startup modifies only
the restored generation. Failure before activation stops/removes the candidate,
reconciles each rename and verifies the original intended service state. Failed
recovery is reported as `rollback_failed`, not `rolled_back`.

`activation_started` is fsynced before final production-network/container creation.
After this boundary, recovery preserves the new generation and attempts bounded
non-destructive startup/readiness reconciliation. It never restores the old
snapshot automatically and discards potential client writes. Unresolved outcomes
remain `needs_attention`; a later rollback requires a new confirmed restore with
its own safety capture.

On success, root-owned `active/<instance>.json`, managed `compose.json` and an exact
Docker create definition record the active image/mounts/profile. Old containers and
generations remain stopped. Data-only restore of an originally stopped service
returns `data_restored_service_stopped` and leaves final restart disabled. Explicit
start-on-completion is opt-in. The managed definitions contain secrets and remain
inside mode-0700 helper state.

`cleanup` with `kind=staging` removes only the operation's private archive/copy
staging. Restore-test runners must first `rollback`, then call
`cleanup` with `kind=discard_candidate`. This action requires a disarmed,
rolled-back/failed-safe restore that never crossed `activation_started`. It
verifies original bind identities, stopped isolated candidate ownership, new
bind-generation identities and labeled local volume provenance. Anonymous volumes
are recorded before removing their candidate container; preexisting or unproven
volumes fail closed. All peer references, including aliases, block deletion.

Cleanup fsyncs its per-resource deletion plan/progress and verifies absence after
each delete. Repeating it is idempotent. A transient filesystem/Docker failure gets
at most three attempts per resource, then retryable `CANDIDATE_CLEANUP_INCOMPLETE`.
The controller must not report disposal complete until
`candidate_cleanup_outcome=complete` and `candidate_cleanup_remaining=0`;
`discarded_candidate_bytes` reports logical generation/anonymous content bytes,
not physical disk savings. Staging is deleted only after candidate resources.
Image-declared anonymous volumes are rejected during new restore validation unless
the mount is explicitly enrolled; cleanup also handles recorded legacy/partial
candidate volumes. `kind=generations` requires successful activation, the recorded safety
acknowledgment, the same active generation and expiry of the root policy's rollback
grace (default seven days). It does not force-remove mounted volumes or running
containers. Image caches and superseded/ambiguous generations are not silently
removed to obtain free space. Preflight reports staging usage and blocks the host
quota (default 100 GiB) or insufficient reserve; operators must explicitly review
protected material when capacity is exhausted.

## Verification and remaining release evidence

Run deterministic tests and loopback SSH boundary tests:

```bash
.venv/bin/pytest tests/unit/test_remote_security.py \
  tests/unit/test_remote_lifecycle.py tests/unit/test_remote_ssh.py -q
```

The optional real Docker and systemd fixtures use separate labeled disposable
containers/networks and private data, never a production instance:

```bash
VAULTREWIND_REMOTE_DOCKER_TEST=1 .venv/bin/pytest tests/unit/test_remote_docker.py -q
VAULTREWIND_REMOTE_SYSTEMD_TEST=1 .venv/bin/pytest tests/unit/test_remote_systemd.py -q
```

Recorded on 25 October 2026:

- The initial real Docker bind/local-volume round trip passed: 2 tests in 227.78s,
  using Docker 26.1.5 and Vaultwarden 1.37.4. It exercised exact-image export/import,
  full capture, safety gating, generation replacement, isolated readiness and
  stopped-state preservation. Its systemd and controller safety-ack boundaries
  were explicit substitutions.
- The real independent systemd watchdog test passed: 1 test in 97.53s. SIGKILL
  immediately after Docker stop left the journal in quiescence; systemd recovered
  the original source independently, verified `/alive`, fsynced the safe outcome
  and disarmed. This is AC22 helper-loss evidence.
- The installed systemd recovery-unit read-only check passed after fixing template
  lookup to use a concrete inactive instance.
- Loopback AsyncSSH tests exercise real host-key verification, framed uploads /
  exports, limits and ambiguous helper exits. They are not an installed remote
  helper or real controller-to-host workflow claim.

The real reboot drill below covers three recovery boundaries. Exhaustive faults
at every boundary, complete UI-to-helper orchestration and alternate-server
public readiness need separate integration evidence. No production deployment
or publication was performed.

### Completed bootable-VM reboot drill

The subsequent AC23 drill passed: **1 test in 1825.36s**, covering three real
reboots of the explicitly authorized disposable QEMU VM, never the controller.
[Machine-readable evidence](evidence/remote-vm.json) records the exact production
helper bundle hash, image identity, snapshot identities and distinct boot IDs.

- Reboot immediately after source stop: the boot reconciler independently recovered
  the original service and fsynced `failed_safe` with a running source.
- Reboot after the first durable old-generation rename: the original generation and
  its later-write marker survived; the service recovered and the journal became
  `rolled_back`.
- Reboot immediately after final start: the restored generation and a fsynced new
  write sentinel survived; the journal became `complete`; the old source remained
  stopped. No old-generation rollback occurred after activation.

The drill used the installed production helper and systemd units, real SSH framing,
real Docker/Vaultwarden, and real encrypted local restic safety commits/readback.
The test's pin ledger was fsynced synthetic bookkeeping; it does not prove the
controller API's database pin workflow. Its write sentinel proves generation
preservation, not authenticated user login or decryption. The harness only read
journals and Docker state while waiting after reboot; it did not invoke controller
recovery to obtain the successful outcomes.

These three VM boundaries are verified for the exact bundle recorded in the
evidence; subsequent cleanup/writer-overlap hardening has separate unit/Docker
coverage. See [the reproducible fixture
instructions](../helper/fixtures/README.md). Initial VM setup exceeded a two-minute
harness timeout under CPU emulation; the setup limit was increased and the same
synthetic fixture reused before any reboot test began.

Latest real Docker bind/volume rerun: **2 passed in 179.22s**. The parent separately
recorded the installed localhost SSH capture/cleanup round trip in
[ssh-capture.json](evidence/ssh-capture.json).

### Safety review follow-up and API target handoff

The final deterministic/loopback SSH suite passed **88 tests, with 7 opt-in tests
skipped, in 5.74s**; source/fixture/test lint passed. Deadline expiry for ordinary
requests, exports and uploads now returns a retryable transport outcome, requiring
journal reconciliation. Safety-export hashing records its worker identity before
reading the archive. Readiness rechecks that the container is still running after
the successful internal probe.

Real Docker disposal tests passed **2 tests in 273.83s**, covering bind and local
named-volume restore-test rollback, anonymous-volume provenance/deletion, verified
new-generation/staging deletion, idempotent repeats, logical-byte accounting and
originally stopped source preservation. An initial source-stop transport timeout
failed before cleanup; the isolated fixture was cleaned and the test was retried.
A separate real parent bind-alias test passed **1 test in 20.32s**; the paths were
canonically distinct, and a stopped restart-capable peer was rejected by physical
identity. These tests use explicit systemd/safety-ack substitutes; they do not add
to the earlier real-systemd/reboot proof.

The VM now also has two separately enrolled empty API targets with independent
bind roots, internal networks and dedicated `.invalid` DOMAIN overlays. Both
passed actual constrained operational SSH preflight with recovery verification.
The existing reboot-drill source, active generation and journals were preserved;
no additional reboot was performed. Private connection/enrollment data is in
`.runtime/vm/controller-enrollment.json` (0600), never in this document or evidence.
Public target identities, adapter cleanup signature, current bundle information
and ROOT's remaining API orchestration are recorded in
[REMOTE-CONTRACT.md](REMOTE-CONTRACT.md). No native controller/source changes were
made for target preparation.

### Real API enrollment of VM targets

The repeatable [VM target harness](../scripts/prove_vm_targets.py) completed real
API8098 activation planning, reviewed helper activation, operational discovery and
registration of the alternate and dedicated runner. A third distinct empty target
on VM loopback 18102 is installed but deliberately absent from the native registry,
for ROOT's independently authorized fresh-controller recovery drill. Private
connection descriptors remain mode 0600 under `.runtime/vm`; public evidence is in
[vm-targets.json](evidence/vm-targets.json).

An interrupted first activation exposed a controller commit gap: host-ready and
revision updates were committed before job completion, and the restarted worker
rejected its own revision change. ROOT owns and reported the atomic-success fix.
A fresh reviewed activation then succeeded. The original separate planning failure
was not reproduced: root authentication and exact bootstrap now succeed, but the
original generic bootstrap error discarded the causal exception. Evidence retains
that uncertainty. This harness performed no application backup/restore or native
service restart and preserved the old VM reboot-drill policy and journals.

### Verified Docker-daemon outage recovery

The explicitly authorized VM daemon stop/start regression passed **1 test in
581.43s**. After a test-only SIGKILL immediately following graceful source stop,
the same production watchdog PID remained active with zero restarts while guest
Docker and its socket were stopped. At 9.4 seconds beyond the original deadline,
the journal still reported armed, failed recovery. Once Docker returned, the
watchdog recovered the source independently, verified readiness, fsynced
`failed_safe`/`source_service_outcome=running` and disarmed.

The fixture removed its own source/container/network/data/staging, restored the
original policy and verified exact old journal hashes, old container running and
restart states, and synthetic post-activation sentinels. VM boot identity was
unchanged and final armed-journal count was zero. The controller Docker daemon
was not touched. [Evidence](evidence/remote-vm-docker.json) records the exact tested
bundle; the subsequent accounting-only fields have separate existing-test checks.

Preflight now returns `source_staging_bytes` for files under `operations/`,
`image_cache_bytes` for files under `images/`, and `staging_quota_bytes` from the
root policy. `staging_bytes` remains their sum. These are the same file-size
accounting semantics as before, not a claim of deduplicated allocated disk blocks.
No new verb, cleanup behavior or automatic image-cache eviction was added.

## Desired restore network and verified public readiness

Capture health and restore public readiness are separate. A running source with
coherent SQLite and working internal `/alive` can be backed up even if Docker
failed to publish its configured host ports. Discovery and preflight report
`current_public_ports_ready` (null when absent/stopped) and a safe
`current_public_error_code`; these fields describe actual allocation, not an
external browser/login check.

The desired restore network comes from root-owned `recovery_profile.network`,
falling back to the current source network or the sole approved network of an
empty target. Desired ports come from `recovery_profile.port_bindings`, falling
back to `port_bindings`. Preserve the old source network in `allowed_networks`
when adding a corrected recovery overlay. Expected host ports require a local,
non-internal bridge using NAT gateway modes. No-public-port runners can use an
internal bridge. IPv4/IPv6 loopback or wildcard bindings are supported; DNS names,
scoped/mapped IPv6, dynamic ports and bindings that cannot be verified through a
literal local endpoint fail closed.

Successful preflight adds `restore_ready` and `restore_error_code`. Only the
known profile errors `PUBLIC_NETWORK_UNPUBLISHABLE` and `PUBLIC_BIND_UNSUPPORTED`
are reported as readiness=false; watchdog, transport and other validation errors
still raise. Systemd verification remains mandatory and happens first. Discovery
also returns these fields and sets `restore_enabled=false` for an unready profile.
This permits a helper safety upgrade while preserving an unsupported instance
without authorizing its restore. Stage restore raises the profile error before
transfer or downtime. Safety preparation checks the staged descriptor again
before arming and stopping the source.

Activation requires both internal application readiness and actual Docker
`NetworkSettings.Ports` matching approved host addresses/ports, then a fixed
loopback HTTP `/alive` check for container port80, or TCP for port3012. Probes do
not use DOMAIN, follow redirects, resolve DNS or accept caller URLs. Empty and
0.0.0.0 IPv4 bindings normalize consistently; explicit loopback/IPv4 policies do
not authorize broader wildcard/IPv6 allocation. A stopped original remains
stopped and does not need a listening endpoint.

After the durable activation boundary, `PUBLIC_PORTS_UNAVAILABLE` or
`PUBLIC_ENDPOINT_UNAVAILABLE` leaves `needs_attention`, preserves current data
and possible writes, and never rolls back. Successful results durably record
`public_ports_verified` and `public_endpoint_verified`. Reconciliation uses the
same checks. Status or idempotent commit for a legacy internal-only completed
journal rechecks the current generation read-only before accepting success;
failure downgrades to needs_attention without restarting, recreating or rearming.
Superseded legacy generations lacking proof report PUBLIC_READINESS_UNVERIFIED.

Real disposable regression, 2026-10-25:
`VAULTREWIND_REMOTE_PUBLIC_DOCKER_TEST=1 .venv/bin/pytest -q -s tests/unit/test_remote_public_docker.py`
passed **1 test in155.65s** on Docker26.1.5+dfsg1. A labelled internal bridge and
new Vaultwarden1.37.4 container had internal readiness but actual Ports={}; its
public check failed PUBLIC_PORTS_UNAVAILABLE. The corresponding non-internal
bridge published the same loopback port and passed host `/alive`. This confirms
the fixture's internal-network publication failure on this Engine version; it
is not evidence of a new Docker28/29 regression.

The same test injected a TEST-ONLY public-probe failure after real container
activation: needs_attention preserved the running container, data inode and new
write. Reconciliation completed only after the real host probe was restored and
passed. All test containers/networks/data were removed. This boundary test uses
a constructed private journal and substituted systemd adapter; full capture,
safety export and actual systemd proofs are documented separately. No VM app,
old journal or native source fixture was mutated for this test.

Remote unit/loopback suite after this change: **152 passed,10 opt-in skipped in
6.55s**. Includes corrected desired overlays for broken source ports, rejection
before arming, empty target rejection, stopped-target preservation, strict
IPv4/IPv6 matching, fixed non-redirecting probe, post-publication preservation,
legacy status downgrade and fatal watchdog/transport failures.

## Review03: running endpoints, restart policy, overlays and repeated volumes

A running application restore now requires an approved host binding for container
HTTP port80. `PUBLIC_ENDPOINT_REQUIRED` is a known preflight readiness=false
result for a running source; staging also rejects an endpoint-free target when
start_on_completion=true, before downtime. No-port runners may validate isolated
candidates and roll back, or perform an explicitly stopped data-only restore.
They cannot produce a running public success. Legacy zero-endpoint receipts are
rejected even when an older journal contains public_endpoint_verified=true.

After an interruption between final-container creation and restart-policy setup,
recovery reapplies the recorded policy and verifies Docker's returned policy
before completing. Data-only recovery verifies restart=no. An ineffective update
leaves needs_attention. Successful activation retires only the proven stopped,
isolated candidate container; it retains all active data and rollback generations.

Vaultwarden gives config.json precedence over environment variables, so an
approved DOMAIN substitution is also applied to config.json in the private new
generation. The captured archive, verified incoming snapshot and old live data
remain unchanged. Mode, owner and extended metadata are retained; effective
configuration is checked before activation. Only DOMAIN substitutions are
supported; unknown settings fail TARGET_OVERLAY_UNSUPPORTED without echoing
values. See the [official configuration precedence documentation](https://github.com/dani-garcia/vaultwarden/wiki/Configuration-overview#configuration-precedence).

Repeated named-volume restores now record actual current mounts from discovery,
including old-volume metadata and directory identity. Cleanup removes the exact
previous volume only after the configured grace, verified safety acknowledgment,
stopped old-container removal and checks that no container still references it.
Active volumes remain untouched. Older journals lacking sufficient provenance
fail closed instead of guessing which volume to delete.

The independent review regressions are in tests/unit/test_remote_review03.py.
All remote unit/loopback tests:158 passed,10 opt-in skipped in6.77s; lint passed.
They cover the zero-endpoint guard, interrupted/ineffective restart-policy update,
config precedence without modifying source snapshots, unsupported overlays,
second named-volume restoration and exact grace-protected cleanup.

## Real stopped/offline local proof

Run `.venv/bin/python -I tests/unit/test_remote_stopped_offline.py --run` as root
in a disposable local Docker environment with cached Vaultwarden1.37.4 and restic.
It creates unique container/network/image identities and private paths, imports
helper/core from helper/.final-bundle/helper.pyz, and cleans only its own fixtures.
The actual run passed in408.39s; hashes and outcomes are in
[stopped-offline.json](evidence/stopped-offline.json).

The test demonstrates AC03 root0600 ownership/modes/content unchanged by capture,
AC06 manual no-Compose recovery, AC10 stopped-source capture and stopped original
restore, and AC11 reload of an absent unique image ID from its saved archive with
pull/build API calls forbidden. A synthetic foreign-platform archive is rejected
before source downtime while the real source remains running with unchanged
StartedAt. AC26 uses a policy reserve above actual measured filesystem free space,
verifying unchanged full data hash/State/StartedAt and zero mutations or watchdog
arms. It never fills shared storage.

The original restore exports its safety archive, commits to a real encrypted
restic repository, reads all restored bytes back and fsyncs a private protected
acknowledgment before switching. An explicit fixture-only start AFTER stopped
restore assertions verifies the approved target URL through real `/api/config`.
No source snapshot config was modified. The temporary containers, network,
unique image, data and encrypted test repository are removed afterward.

This is helper integration evidence, not a worker or systemd test: systemd is
substituted, and the controller pin is a fsynced fixture record instead of a
controller database row. The host network is not globally disabled; registry
unavailability is enforced at the Docker pull/build API boundary. Shared base
layers remain cached while the unique recorded image identity is absent.
The tested bundle9955c8646d521b7bbec50db93b9416b327265b33d3c366d7004dc2b5560c5883
is retained in helper/.review03-tested. Final bundle
8e7775f757002f07f67d6d3616f5288186f75291c352ab19409f44e09a51bf0d
adds the unit-tested legacy zero-endpoint receipt guard. Current-source public
failure/preservation regression also passed1 test in45.07s.

## AC24 preactivation fault harness

`VAULTREWIND_REMOTE_FAULT_DOCKER_TEST=1 .venv/bin/pytest -q -s tests/unit/test_remote_fault_docker.py`
launches an isolated Python process importing the frozen helper/core zipapp
8e7775f757002f07f67d6d3616f5288186f75291c352ab19409f44e09a51bf0d.
It operates only on new uniquely labelled local Docker containers, a named data
volume, a private bind configuration directory, and temporary storage. No helper
source/bundle changes, installations, VM access or primary-source operations are
part of this test.

Two actual framed archive transfers are damaged: a truncated trailer and a
flipped payload byte with unchanged checksum. The harness requires rejection
before Docker mutations, watchdog arming or generation materialization, with
unchanged running state/StartedAt, restart policy, private file metadata and
SQLite logical contents. It then safely reconciles and discards each failed
operation's private staging.

A valid restore exports its safety snapshot to a real encrypted local restic
repository and verifies full readback before a fsynced fixture pin/ack. The
TEST-ONLY Docker adapter injects APPLICATION_NOT_READY after the real isolated
candidate has started and passed internal `/alive`. It adds an anonymous volume
solely to exercise legacy/partial-state cleanup; normal release enrollment
rejects such an unapproved mount. This is a failed readiness-decision test, not
evidence of an actual application crash.

The harness requires rolled_back, watchdog disarmed, no activation boundary,
original running/public-ready, the expected changed StartedAt after recovery,
restored restart policy, original root0600 file/config hashes and identities,
and unchanged SQLite logical contents. Repeated discard_candidate must remove
the private bind generation, candidate named and anonymous volumes and operation
staging while preserving original data. The optional two-restore check uses real
named volumes, proves the rollback grace blocks early deletion, then advances
only the fixture journal deadline and verifies the exact prior volume disappears
while the active volume remains. No global clock is changed.

Systemd orchestration is substituted and the controller pin is a private fsynced
fixture record rather than a worker database row. This supplements the separately
executed watchdog/VM proofs and does not claim full worker failure coverage.
Machine-readable results are recorded in
[preactivation-faults.json](evidence/preactivation-faults.json) only after final
fixture cleanup and bundle checksum verification.

Executed result: **1 passed in575.83s (9m35s)**; harness measured575.05s.
Both actual damaged transfers were rejected without target mutation. The real
candidate readiness-decision fault recovered the original running/public-ready
service and exact protected file/config metadata and logical SQLite contents.
Idempotent candidate disposal removed the actual bind generation, named and
anonymous volumes, and operation staging. Both optional real named-volume
restores passed: grace refusal was verified, then exact prior-volume removal and
active-volume preservation were confirmed through Docker. All owned fixtures
were removed. Ruff passed and the frozen8e7775 bundle checksum remained unchanged.
No helper implementation/bundle edits, installation, VM or primary-source calls
were made. This remains helper-level evidence with the explicit fault/systemd
limits above; it does not claim a real application crash or worker failure test.

## Historical status and reviewed helper upgrades

Polling a completed restore whose active pointer now names another operation
preserves its terminal audit result. Legacy results without public proof expose
`historical_public_readiness=unverified`, `historical_warning_code=PUBLIC_READINESS_UNVERIFIED`
and false public-proof flags. They do not claim that the retired container still
serves, probe it, or restart it. Existing recorded public proof is retained as past
proof. A currently active legacy generation still requires verified readiness;
a failure remains needs_attention and blocks new operations.

A narrow migration repairs the previously introduced status-upgrade error only
for an unarmed restore in needs_attention with exact PUBLIC_READINESS_UNVERIFIED,
an original completed activation in its history, no live/malformed owner, and no
prior successful public proof. Its active registry must identify a different,
newer terminal restore with matching image, descriptor hash, operation/instance
ownership, container name, physical generation identities and all mounts. The
successor must have candidate HTTP/SQLite validation and the correct restart
policy. Running successors require recorded nonzero public proof and a fresh
read-only Engine/approved loopback endpoint check. Intentionally stopped
successors must still be stopped with restart=no and no allocated public ports.
The successor journal and active registry are reread after the probe; changed,
missing, malformed or unavailable evidence refuses repair.

Operational `status` can perform this exact repair while holding the existing
host/resource locks, before live fencing. It neither changes fencing records nor
ignores unrelated pending work. Repair appends a historical_status_reconciled
history event containing the previous raw journal SHA256, prior error and proven
successor ID; all original history, error and health evidence remain. Public
flags remain false for the old operation. Repeating status is idempotent. Explicit
recovery also refuses to start a retired container when a newer active journal
exists.

The administrator API is Python-only; no new remote protocol verb is exposed:

```python
from vaultrewind.remote.helper import Helper
from vaultrewind.remote.policy import Policy

service = Helper(Policy.load())  # installed root-owned policy
proof = service.reconcile_historical_status(operation_id)  # read-only dry-run
# Administrator reviews proof and saves a private, hash-verified journal backup.
# Only for an eligible record and the exact reviewed raw journal digest:
result = service.reconcile_historical_status(
    operation_id, apply=True, expected_sha256=proof["journal_sha256"]
)
```

A changed digest raises JOURNAL_CHANGED; an unproven record returns eligible=false
without mutation. The validator imports must come from the checksum-reviewed
candidate or newly installed helper, not an older helper or writable search path.
Do not hand-edit phases or remove reservation journals.

For a product upgrade blocked by only these historical records, the fixed admin
bootstrap may import the trusted candidate bundle and use
`historical_status_evidence_locked(operation_id)` under `Locks(service.root, [])`.
This has the same dry-run predicate but deliberately does not acquire a second
lock. Enumerate all pending records under that lock; require every record eligible
and compare the exact operation IDs, raw hashes and successor IDs with the
reviewed activation plan. Any armed record, including a terminal one, blocks.
Keep the host lock through installation, and preserve the installed policy's
instance entries in the replacement policy. Installation admission does not
modify journals. After installation, normal status performs the narrow repair.
ROOT owns this BOOTSTRAP/activation-plan wiring; it is not automatically installed
by the remote helper changes. Existing installer/unit validation stays mandatory.

Verification used unique temporary filesystem journals and explicit Docker and
systemd unit doubles: **254 remote tests passed, 11 opt-in tests skipped in 28.56s**.
The **70 historical regression cases passed in 10.62s** and include two successive
restores followed by a third, repair of two independently corrupted histories,
unrelated armed-operation fencing, current unverified readiness, hash-checked
admin apply, host-lock retention, named-volume provenance, stopped successors,
malformed ownership and proof changes during the endpoint probe. No shared
native/VM state was read or mutated; this migration is not a new real-host proof.
Ruff passed for the remote source, build/install scripts and affected tests.

Review candidate: `helper/.final-bundle/helper.pyz`, SHA256
`cbf84b999eab462a6ad08b86ef06c631c148e796d242459f227c79df2a0a0093`.
Compared with ROOT's 71cb458d candidate, only remote/helper.py and remote/journal.py
changed inside the zipapp. ROOT's Docker.stop acknowledgement reconciliation and
core safe-error serialization are preserved. The installed/runtime bundle was
not changed or activated. The previous 8e7775 artifact is retained under
`helper/.frozen-8e/`; the AC24 harness now references that archived artifact so its
recorded proof remains reproducible independently of later candidate builds.
The same 70 historical cases also passed against imports from the built candidate
zipapp (not source imports) in 10.61s. Bundle members were checked against source;
its checksum and the unchanged runtime8e checksum were verified after testing.

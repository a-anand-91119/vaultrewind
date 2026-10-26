# Authenticated synthetic recovery drill

This opt-in engineering drill complements the completed structural recovery
proofs with real client encryption and authentication (AC07, AC08 and AC31).
It creates one disposable account, login item and binary attachment in a new
Vaultwarden 1.37.4 Docker fixture. It uses VaultRewind's running loopback API,
worker, enrolled SSH transport, frozen helper and encrypted LOCAL destination.
It does not use production, Google Drive, S3, VM 22229 or existing vault data.

## Run boundaries

`scripts/prove_authenticated_recovery.py` defaults to preparation with no file,
network, controller or Docker access:

```sh
.venv/bin/python scripts/prove_authenticated_recovery.py
.venv/bin/pytest -q tests/unit/test_authenticated_recovery_drill.py
.venv/bin/ruff check scripts/prove_authenticated_recovery.py tests/unit/test_authenticated_recovery_drill.py
```

Execution requires a new UUID4 run ID. The script generates a separate UUID4
instance ID and accepts no arbitrary host, endpoint, data path or existing
instance. Runtime files live under `.runtime/authenticated-recovery/<runUUID>`;
directories are 0700 and credential/checkpoint files are 0600. No vault export is
created. Retain credentials privately for optional manual review.

```sh
.venv/bin/python scripts/prove_authenticated_recovery.py --execute --run-id RUN_UUID --stage plan
.venv/bin/python scripts/prove_authenticated_recovery.py --execute --run-id RUN_UUID --stage activate --reviewed-plan-id PLAN_UUID
.venv/bin/python scripts/prove_authenticated_recovery.py --execute --run-id RUN_UUID --stage prove
```

After `plan`, the parent reviews the exact plan ID, new instance UUID, proposed
policy hash, preserved profile hashes, frozen helper hash and old journal map
hash. This is serialized coordination with the parent implementation thread.
`activate` requires that exact plan ID and an unchanged baseline. It does not
rebuild the helper. The packaged and installed helper must both hash to
`cbf84b999eab462a6ad08b86ef06c631c148e796d242459f227c79df2a0a0093`.

The native host is derived from existing source UUID
`46ac8eb9-1854-4fc6-924f-af14c6b7d0c2` and must resolve to loopback SSH port 22.
The source is only an identity lookup, never a mutation target. Every prior
helper profile and journal must remain identical. Activation's controller
bookkeeping legitimately advances revisions/timestamps and reseals encrypted
configuration. Semantic prior configuration, resource identities, schedules,
timers, budgets, destinations, snapshots and copies remain unchanged.

The new source uses a dedicated ordinary Docker bridge with port 18280 bound
only to 127.0.0.1. SMTP is unconfigured, push and icon downloading are disabled,
and application logging is off before registration. The browser rejects every
nonfixture origin. This source network is **not an air gap or container egress
firewall**. Candidate validation uses the product helper's network-none runner.

The bundled client SDK rejects HTTP, including loopback, before sending account
requests. A run-owned TLS proxy binds only `https://127.0.0.1:18443` and forwards
unchanged requests/responses to the exact new HTTP fixture. Its generated key
and certificate stay in private 0600 files. The official CLI trusts that
certificate through `NODE_EXTRA_CA_CERTS`; Chromium pins its public-key SPKI for
this local test. No API response, account record, encryption or client code is
fabricated. The product's native endpoint remains HTTP loopback 18280. This is
an explicit TLS fixture adapter, with no daemon/global trust/service changes.

## Official client and private channels

The official Bitwarden Linux CLI is pinned to **2026.9.0**, release archive
SHA-256 `580c1deec8345b19dbac7f8b02babb6cc4fe250c69c567e29061f727f1e40768`.
The binary is downloaded only inside the new run's private tools directory.
Official source pages are captured privately and their URLs/hashes appear in
safe evidence. Primary references:

- [Official CLI documentation](https://bitwarden.com/help/cli/)
- [Official pinned CLI release](https://github.com/bitwarden/clients/releases/tag/cli-v2026.9.0)
- [Official release asset digests](https://api.github.com/repos/bitwarden/clients/releases/tags/cli-v2026.9.0)
- [Vaultwarden 1.37.4 release compatibility notes](https://github.com/dani-garcia/vaultwarden/releases/tag/1.37.4)
- [Pinned create/edit command declarations](https://github.com/bitwarden/clients/blob/cli-v2026.9.0/apps/cli/src/vault.program.ts)
- [Pinned stdin reader and password handling](https://github.com/bitwarden/clients/blob/cli-v2026.9.0/apps/cli/src/utils.ts)
- [Pinned create implementation](https://github.com/bitwarden/clients/blob/cli-v2026.9.0/apps/cli/src/vault/create.command.ts)
- [Pinned edit implementation](https://github.com/bitwarden/clients/blob/cli-v2026.9.0/apps/cli/src/commands/edit.command.ts)

The pinned declarations and implementations confirm create/edit payloads can
arrive through stdin. The CLI receives the master password through its documented
`--passwordenv` channel and sessions through `BW_SESSION`; neither value is a
command argument. Login email is supplied to the official interactive prompt
over stdin. Every CLI session has its own `BITWARDENCLI_APPDATA_DIR`. The script
does not modify `HOME` and excludes unrelated inherited credentials from CLI
environments. Server configuration must equal the exact new loopback origin
before login (`https://127.0.0.1:18443` for the pinned TLS fixture).

The CLI has no registration command. The image's bundled real Web Vault performs
registration and client-side key generation. This is not a fabricated account
row or custom cryptographic implementation. T3 `preview_status` and `preview_open`
were attempted first; open returned the explicit root Chrome sandbox unsupported
error. Repository-documented Playwright fallback is used without server changes.
Screenshots, trace, video, console capture, network-event capture and storage
state exports are disabled. Credentials enter the browser driver through stdin.
The registration driver waits for the official successful
`accounts/register/finish` response; an intermediate signup page is not account
creation. Optional external password-breach lookup is disabled in this isolated
synthetic procedure. The actual bundled Web Vault identifies as 2026.7.0 and its
server compatibility response as 2026.6.0. CLI compatibility is established by
the actual login/unlock and decrypted byte checks, rather than inferred from
the release notes.

## Proof sequence and reconciliation

1. Create and label a new fixture; verify image, exact mount, network and loopback
   binding. Refuse active controller jobs or pending helper operations.
2. Plan and activate only the new helper profile, preserving every prior profile
   entry and journal hash. Discover/enroll the new instance through the API.
   Disable its backup schedule and require only the existing LOCAL destination
   `c59b1b7c-810e-4ebe-a7bf-d5d559891f1d`.
3. Register with the actual Web Vault. In a new official CLI appdata directory,
   log in, unlock, sync, create an encrypted login item, and upload an attachment.
4. Ask the native API/worker for a complete capture and exact LOCAL copy.
5. In another fresh CLI session, change the login password, delete its attachment,
   and create a post-capture marker item. Sync and verify those changes.
6. Bind a restore plan to the exact snapshot/copy and the new fixture target.
   Execute once through the native API. Require a pinned complete LOCAL safety
   snapshot before replacement and successful application/byte validation.
7. Create a completely new CLI appdata/device/session after restoration. Log in,
   unlock, sync, decrypt and compare the original item; prove the marker absent;
   download/decrypt the restored attachment and compare bytes and SHA-256.
8. Verify prior resources, semantic policies, profile entries and journals;
   retain the restored fixture and encrypted points with schedules disabled.

Stable per-run keys and checkpointed job IDs prevent blind duplicate jobs.
After a lost response the harness queries the exact idempotency key and waits
for that job. Unresolved nonjob writes stop for diagnosis. A failed restore is
never replaced by a newly submitted restore. After possible activation failure,
retain the current generation and use read-only diagnosis. Failed attempts and
their checkpoints are retained; no existing fixture cleanup occurs.

Public snapshot views omit the manifest hash. The harness reads that safe hash
from the exact new instance's Snapshot/SnapshotCopy/Repository rows, with all
three identities checked, while backup and restore execution remain native API
and worker operations.

The public JSON report is an explicit safe allowlist of IDs, hashes, booleans,
client versions and scope. It never serializes the private checkpoint. Private
random credentials, session values, item payloads and tool output are not printed.
This proves the dedicated synthetic account's item and attachment only. It does
not assert that production users, every client version, organizations, passkeys,
2FA or external identity providers have been authenticated.

## Recorded execution

The final run IDs, job IDs, hashes and result are recorded in
[`evidence/authenticated-recovery.json`](evidence/authenticated-recovery.json).
The actual native API/worker/SSH proof **passed** on 26 October 2026 UTC:

- Run: `473e089d-87cb-40be-8cc0-d19dbed789b3`.
- New instance: `a219284d-ccfc-4522-b5ac-e44faaea3994`.
- Reviewed activation plan: `7ce94aa8-55d5-4085-a311-275b00d1b113`.
- Backup job: `deaa4ff0-072e-47a2-bb87-209aada0e420`.
- Selected snapshot: `82caebb1-3187-4da5-a058-4550f4c3e2d5`.
- Selected LOCAL copy: `9536457c-906f-449f-8882-0fefb9f923c9`.
- Restore plan: `a728fe12-f9b0-416e-9188-f607dac815cb`.
- Restore job: `bf2489cf-cef6-49fa-8627-fbb7779af475`.
- Pinned complete LOCAL safety snapshot: `efadd5bd-10d4-4cef-9c5a-876b31bffff2`.
- Decrypted attachment SHA-256:
  `b0c2b08d6dd243d703f7d055fb991dd4dae98ce3100cebca4b937162b3208666`.

Three separate CLI appdata/device/session contexts performed login, lock,
unlock and sync. The third, created after restoration, decrypted the original
item name, username and password; the changed password and post-capture marker
were absent. The deleted attachment returned and its decrypted download matched
the original private 65,536-byte file byte-for-byte and by SHA-256. Sessions were
logged out. No plaintext vault export was created.

The terminal API result, helper journal and helper final-health evidence each
explicitly reported `public_ports_verified=true` and
`public_endpoint_verified=true`. The helper journal was `complete`, its watchdog
was disarmed, and its active generation matched the exact restore job. Read-only
inspection confirmed the old generation's original device/inode identity and
its stopped rollback container were retained.

The safety acknowledgment explicitly recorded durable, encrypted, pinned and
stored-copy-verified facts bound to the same safety snapshot/repository/restic
IDs. The worker's restic commit reads back the manifest and checks the stored
tree against inventory before returning that acknowledgment. The drill then
rechecked the exact acknowledgment and pinned complete LOCAL catalog copy.
**This is not an independent full restore/read of the safety snapshot or a new
full repository data check.** Those were not performed by this drill.

Both prior helper profiles and every one of the 19 prior journal hashes remained
identical. Existing semantic instance configuration, policies (including schedule
enabled state, timers, budgets and destination assignments), snapshots, copies,
native container identity/start-state witnesses and controller master hash all
matched their baseline. This does not assert a newly repeated full inventory
hash of every existing live vault. No existing vault data, grants, VM fixtures
or production resources were mutation targets. The new schedule remains
disabled and LOCAL is its sole required destination. No native jobs remained
active at settlement. The restored fixture, its old generation, encrypted points,
private credentials and TLS adapter were retained for private review; no fixture
cleanup was performed.

The product job's `user_login_tested` annotation remains `false`. The successful
authenticated procedure is this separate engineering evidence; it does not
silently enable or relabel product-managed authenticated verification.

Observed commands and results:

```sh
.venv/bin/python scripts/prove_authenticated_recovery.py
# prepare; mutations=false; external_io=false
.venv/bin/python scripts/prove_authenticated_recovery.py --execute --run-id 9adb414d-5eaa-40c3-aa34-e6091e1f04fc --stage plan
# retained preparation failures listed below
.venv/bin/python scripts/prove_authenticated_recovery.py --execute --run-id 473e089d-87cb-40be-8cc0-d19dbed789b3 --stage plan
# passed; reviewed plan 7ce94aa8-55d5-4085-a311-275b00d1b113
.venv/bin/python scripts/prove_authenticated_recovery.py --execute --run-id 473e089d-87cb-40be-8cc0-d19dbed789b3 --stage activate --reviewed-plan-id 7ce94aa8-55d5-4085-a311-275b00d1b113
# passed
.venv/bin/python scripts/prove_authenticated_recovery.py --execute --run-id 473e089d-87cb-40be-8cc0-d19dbed789b3 --stage prove
# retried from exact checkpoints after diagnosed harness failures; final passed
.venv/bin/ruff check scripts/prove_authenticated_recovery.py tests/unit/test_authenticated_recovery_drill.py
# all checks passed
.venv/bin/pytest -q tests/unit/test_authenticated_recovery_drill.py
# 19 passed in 0.69s (focused result; whole-suite integration is the parent's work)
```

The final report also contains read-only post-proof checks of API/helper public
flags, exact safety/generation identities and the failure history. These checks
did not create jobs or run another authenticated client session.

## Retained failure chronology and scope exception

All eight checkpointed failures are preserved privately and copied as safe
codes/timestamps/run IDs into the public JSON. No failed attempt was erased:

1. **19:22:10 UTC**, preparation run `9adb414d-5eaa-40c3-aa34-e6091e1f04fc`,
   `CLI_STDIN_SOURCE_MUST_BE_REVIEWED`: the first source guard looked only at
   the CLI entrypoint. It was corrected to verify the actual create/edit command
   modules and stdin reader before client payload use.
2. **19:24:50 UTC**, same preparation run, `NEW_FIXTURE_STARTUP_FAILED`:
   Docker's internal-only bridge did not publish its requested host port. The
   failed new fixture was retained, and a new run used an ordinary dedicated
   bridge. No activation/enrollment/backup occurred for the failed fixture.
3. **19:31:41 UTC**, main run, `PRIVATE_COMMAND_FAILED`: real Web Vault
   registration did not advance from its email/name form.
4. **19:33:08 UTC**, main run, `PRIVATE_COMMAND_FAILED`: safe form diagnostics
   and official client source review identified the SDK's HTTPS requirement.
   No account existed. The private TLS adapter resolved that prerequisite.
5. **19:39:46 UTC**, main run, `CLI_LOGIN_FAILED`: an overly broad intermediate
   signup-URL condition closed the browser early and falsely marked the UI step
   complete; the actual CLI correctly rejected login because no account existed.
   No successful authentication was claimed. The completion guard was corrected.
6. **19:41:18 UTC**, main run, `PRIVATE_COMMAND_FAILED`: signup remained at the
   password form with optional breach lookup selected. Nonfixture requests were
   blocked; the driver was corrected to disable that optional external lookup.
7. **19:43:16 UTC**, main run, `PRIVATE_COMMAND_FAILED`: the real client created
   the account, but the expected final UI route was not recognized. Read-only
   exact-account reconciliation prevented another registration, and real CLI
   login/unlock/sync subsequently succeeded. The final driver uses the official
   successful `accounts/register/finish` response as its completion boundary.
8. **19:47:36 UTC**, main run, `PRIVATE_FAILURE`: the native backup had succeeded,
   but the harness looked for a manifest hash omitted by the public snapshot
   view. The own-catalog identity check described above corrected this; the
   existing succeeded backup job was reused, with no second capture.

There was also one concrete scope exception at **19:22:06 UTC**: the initial
`bw --version` probe ran before its appdata environment was scoped, and wrote
24 bytes of version-only state to `/root/.config/Bitwarden CLI/data.json`.
Read-only inspection confirmed only version metadata, with no account, vault,
credential or session content. Its SHA-256 is
`2ae831f873e666cd3366f6f5e2e152c338861c13d468b729be8b4195ac2dd890`.
The file was left untouched. All authenticated commands used private per-run
appdata. Version and authenticated commands now share the same scoped minimal
environment, with a regression test. This exception is disclosed in the JSON
and to the parent; it is not an authenticated-credential scope exception.

Private diagnostics also rejected a relative output path and an inspection of
the not-yet-created new container; those read-only preparation errors changed no
fixture. No product source change was needed for any drill failure.

Remaining boundaries are one synthetic user/login/attachment, one frozen server
image and pinned CLI version, a separate local TLS test adapter, an ordinary
bridge with no claim of an egress firewall, and no independent full safety
readback. The TLS proxy accepts at most 4 MiB per request and reads at most
64 MiB per response; this drill used a 64 KiB attachment. It is not a production
TLS/reverse-proxy deployment or a test of organizations, external identities,
passkeys, 2FA or real user accounts.

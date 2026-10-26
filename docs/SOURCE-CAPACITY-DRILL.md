# AC26 physical source staging capacity drill

Status: **passed for physical remote SOURCE staging-full** after ROOTGO.
[Evidence](evidence/source-capacity.json) records **3 physical integration cases
passed** in **165.664 seconds**. Existing capacity and stopped/offline evidence
is unchanged. Staging-run focused validation: **33 unit tests passed, 0 failed,
0 skipped**; Ruff passed; both new Python files compiled in memory. The ungated
invocation exits 2 without mutation.

A separate **live-data filesystem-full extension passed** in **231.942
seconds**, with **44 focused unit tests passed, 0 failed, 0 skipped**. There are
now **4 passing physical cases** across the two separate fixture runs. The
original staging PASS, detailed source/backup evidence and first failed-attempt
history remain intact; the extension is nested under `live_data_filesystem_full`.

The live-data run began at `2026-10-25T21:06:20.796232+00:00`. Its private tmpfs
had **16,777,216 total bytes**, with **15,933,440 bytes** in the filler outside
`/data`. The filler reached actual **errno 28 / ENOSPC and zero free bytes**;
helper staging independently had **112,324,378,624 free bytes**. Actual helper
preflight passed, followed by a **coherent capture and verified source resume**.
The fault operation used exactly **1 graceful stop**, exit code **0**, no OOM,
and **0 forced kills**. Internal HTTP `/alive` passed while full both before
capture and after source resume.

Free bytes were **0** immediately before stop at
`2026-10-25T21:09:43.896933+00:00`, after stop at
`2026-10-25T21:09:50.084423+00:00`, before start, after start, after HTTP health,
and at capture completion. All **16 sampled boundaries** between fill and
release were zero-free in this run. No WAL-space release was observed at those
boundaries; continuous fullness is **not** claimed. Removing only the outside
filler restored **15,933,440 free bytes**, with the original service healthy.

The same original container resumed normally, changing PID **507120 → 508674**
and its start time/raw data-tree digest. The read-only logical SQLite digest
remained `3274f9dd18d109151904244fc66ba0d7e2adcc8433866c22f9be37723e75d4a6`;
the complete non-database content/metadata digest remained
`c8815fbc00f9b6cd9d85b764cb9da52078d25894853629b6d18328277e6efa99`.
The captured staged snapshot independently matched the pre-fault logical
content. This is a fresh real Vaultwarden schema with **29 tables**, **57
migration rows**, empty user/vault-record tables, and synthetic private file
content; it is not an authenticated user workload.

The older encrypted snapshot
`a86935838544376f6091e5a848dcd46992796f9704840d0ebd41b64c15bbebb3`
passed full restic data verification with **0 errors / 0 broken packs** and
verified restore of **13 files / 303,875,959 bytes**. Manifest verification
covered **10 inventory members / 303,870,208 logical bytes**, and the saved
image, private file, stored manifest, snapshot set and repository bytes matched.
Those repository checks ran after filling and before fault capture, with zero
free bytes sampled before and after verification. Cleanup removed the unique
container, network, mount and workspace: **0 containers, networks or mounts
remaining; 0 cleanup errors**. No product/helper changes or possible product
defect were observed.

After the distinct ROOTGO_DATA_FULL reservation is released, run:

```sh
.venv/bin/python -I -B scripts/prove_source_capacity.py --live-data-full --rootgo-data-full
```

This starts a fresh unique fixture and obtains a real HTTP-healthy baseline and
older encrypted helper-created backup as above. The live `/data` directory is a
child of its private 16 MiB tmpfs. A bounded filler is created **outside** that
enrolled directory on the **same** filesystem, with at most 16 MiB + 1 byte
attempted. Helper staging and the encrypted repository stay on a healthy,
independent filesystem. Real ENOSPC and zero free bytes are required. The older
backup's full restic check and verified byte restore run with zero free bytes
sampled immediately before and after; operation/capture entry must still be
zero-free.

Actual helper preflight and capture may reject before stop or complete a normal
coherent controlled capture and verified source resume. The latter must pass
HTTP `/alive` after resumption and preserve logical SQLite schema, every table's
rows/counts, database ownership/mode, and the non-database tree's content and
metadata. The logical digest uses a closed read-only transaction honoring WAL,
with no immutable shortcut or source normalization. Raw SQLite file bytes,
source PID, and start time may change across legitimate stop/restart. A newly
captured staged snapshot must independently match the original logical content.

Free-space/time/running-state samples are taken at fill, older verification,
operation entry, immediately before/after actual source stop/start, HTTP health,
and capture completion. Graceful stop may checkpoint/delete WAL and release
blocks. The scope is **filesystem full at operation entry**, with no continuous
fullness claim. Unexpected capture or health failures retain truthful evidence;
only the exact outside-data filler is released, and the original container's
HTTP health and logical content are checked. Unverified recovery retains the
private journal/data/container/mounts for repair instead of destroying them.

The successful run began at `2026-10-25T20:37:58.936484+00:00`. Its dedicated
staging tmpfs had **8,388,608 total bytes**, **8,384,512 filler bytes**, and
**0 free bytes**, with actual `OSError(errno.ENOSPC)` / errno **28**. A real
positive preflight passed at reserve zero before the same mount was reduced
and filled. Its advertised sparse capacity before reduction was 1,205,907,152
bytes, covering the real helper estimate of 1,201,712,848 bytes plus 4 MiB;
the filler never allocated that advertised capacity.

Actual preflight dispatch and direct capture entry both returned
`INSUFFICIENT_SPACE`. Capture dispatch hit physical ENOSPC while writing durable
admission records before its inner preflight. Each case made **0 Docker
mutations, 0 source stop calls, and 0 recovery arms**. Before/after/final source
records match exactly: container `e9158b3e0ef1…`, PID **459186**, running,
start time `2026-10-25T20:39:09.244319119Z`, restart count zero, unchanged restart
policy, and data/metadata digest
`4cec0ab83ea43b1dc5d59183ffb3c8d54a3756abc8ab5c8ee903460f69e5d2bb`.
The earlier successful baseline capture's stop/restart is recorded separately.

The older encrypted snapshot is
`5aa7be9d0632e60f21917e5e4f7c50b3f5c68f7398061577af69de357a445e4e`.
Real restic **0.19.1** `check --read-data` read the complete repository with
**0 errors and 0 broken packs**. Verified restore read back **13 files /
303,875,962 bytes**, followed by manifest verification of **10 inventory members
and 303,870,212 logical bytes**. The stored manifest, repository byte digest,
snapshot set, synthetic private file and saved image identity all verified.
These checks ran while remote staging remained full. No application-startup
after restore or user-login claim is made.

Cleanup removed the one unique container, its one private network, both tmpfs
mounts, and the temporary workspace: **0 containers, 0 networks, 0 mounts
remaining, 0 cleanup errors**. No native/controller/VM/shared MinIO calls,
helper installation, daemon restart, image build, or image mutation occurred.

One failed attempt is retained under `failed_attempts`, including its original
217.776-second result and clean teardown. It reached no fault case: the
harness's path-only tmpfs remount command failed before filling. A separate
small private probe isolated the command issue; supplying `-t tmpfs` and the
original tmpfs source fixed it. The first attempt's baseline had safely resumed.
This was a harness defect, with no product capacity failure observed. The
regression test checks the corrected remount arguments, and retry evidence
tests prevent the first attempt from being lost or duplicated.

The harness uses frozen helper bundle
`helper/.final-bundle/helper.pyz`, SHA-256
`cbf84b999eab462a6ad08b86ef06c631c148e796d242459f227c79df2a0a0093`.
It checks that pin and compares shipped helper source with current source before
loading any helper code. Run it in a fresh process so previously imported modules
cannot silently replace the frozen implementation.

Only after root releases the shared Docker mutation reservation with ROOTGO:

```sh
.venv/bin/python -I scripts/prove_source_capacity.py --rootgo
```

Without `--rootgo`, the program exits 2 before loading runtime modules, creating
directories or evidence, mounting filesystems, or accessing Docker.

The bounded procedure is:

1. Allocate a UUID-private mode-0700 workspace below `/root`. Create a dedicated
   16 MiB tmpfs with the entire synthetic live `/data` tree in a child directory;
   the child is an ordinary bind root, as required by helper policy.
2. Start the already installed Vaultwarden 1.37.4 image by immutable image ID in
   a new labeled container on a new internal network, without published ports.
   Require real internal `/alive` readiness. Do not pull, build, commit, or load
   images. Add a root-owned mode-0600 synthetic private file and configuration.
3. Call frozen `Helper.dispatch(capture)` against a separate private baseline
   state directory. This performs a real controlled stop, complete capture,
   restart, staged SQLite normalization, exact image save, and manifest sealing.
   Commit that older snapshot using the real encrypted restic adapter. All
   repository passwords are random and remain in private adapter channels.
4. Create a separate tmpfs for remote source staging. Initially advertise only
   the helper's conservative estimate plus 4 MiB, capped at 2 GiB; this is sparse
   capacity, not allocated memory. Require actual helper preflight success at
   reserve zero, then remount that same tmpfs at **8 MiB** and fill it using
   non-sparse writes. Stop after at most 8 MiB + 1 byte attempted. Require an
   actual `OSError(errno.ENOSPC)` and kernel free bytes equal to zero. The source
   tree, encrypted repository and baseline helper state are on other filesystems.
5. Call real `Helper.dispatch(preflight)` and `Helper.capture` with a durable
   journal prepared before exhaustion. Require `INSUFFICIENT_SPACE` before any
   writer stop, restart-policy mutation, or recovery arm. Also call real
   `Helper.dispatch(capture)`: its durable admission writes precede capture's
   own preflight, so this case must report physical ENOSPC at admission, with
   no writer stop. It is recorded separately from explicit preflight rejection.
6. Compare container ID, PID, running state, start time, restart count and policy,
   and a full source tree digest including bytes, namespace, modes, ownership
   and modification times. Require zero Docker mutation calls and zero recovery
   arms throughout the fault observations. The baseline older capture's earlier
   stop/restart is outside this observation interval and is not counted as zero.
7. While source staging remains physically full, require the exact older restic
   snapshot set and stored manifest, a full `check --read-data`, and `restore
   --verify` plus manifest verification. Verify the saved Docker image archive
   against the original image ID and compare the synthetic private file. Require
   repository bytes and the source process/content to remain unchanged.
8. Remove only exact containers/networks carrying this run's UUID label. Delete
   only their own anonymous volumes if any. Check exact mount identities before
   unmounting, never use lazy/forced unmounts, and never unmount a live container's
   source. Remove the private workspace only after successful cleanup. Save safe
   failure classifications and retain the workspace if cleanup cannot finish.

Pure checks, permitted before ROOTGO:

```sh
.venv/bin/python -m pytest -q tests/unit/test_source_capacity.py
.venv/bin/ruff check scripts/prove_source_capacity.py tests/unit/test_source_capacity.py
.venv/bin/python -I scripts/prove_source_capacity.py
```

The tests use in-memory simulated writers for safety invariants; they do not
substitute for physical evidence. Compilation should use `compile()` in memory
when preserving the four-file ownership boundary.

Systemd verification/arming/disarming is a journal-writing double. This drill
makes no new independent watchdog, reboot, controller-loss, SSH, API/browser,
cloud, authenticated login, or application-startup-after-restore claim. It does
not exercise the optional post-preflight disk race. The original staging cases
leave the live-data filesystem writable; the separate extension tests a full
live-data filesystem at operation entry. Neither fixture claims every possible
source filesystem failure or a full filesystem under an authenticated workload.
The existing controller-full/missing-mount/cloud-capacity evidence and real
provider credential evidence retain their separate scopes.

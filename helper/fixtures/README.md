# Disposable host recovery drills

`vm_fault.py` is **test-only** code. It is intentionally outside the source
package and never copied into the production zipapp. It creates only a labeled
synthetic Vaultwarden instance and pauses a helper at a selected durable boundary.

`tests/unit/test_remote_systemd.py` creates temporary uniquely named runtime units
on an explicitly opted-in disposable Linux/systemd host. It kills a capture helper
with SIGKILL immediately after graceful Docker stop and verifies independent
watchdog recovery. Run only against synthetic fixtures:

```
VAULTREWIND_REMOTE_SYSTEMD_TEST=1 .venv/bin/pytest tests/unit/test_remote_systemd.py -q
```

For AC23, `tests/unit/test_remote_vm.py` targets **only** the already prepared
QEMU fixture at `root@127.0.0.1:22229`, with the key and verified known-hosts file
under `.runtime/vm`. The VM must have Python 3.13, Docker, sudo, systemd and the
marker `/root/vaultrewind-fixture-ready`. No package installation is performed by
the drill. It must be a fresh disposable VM with no unrelated application. The
controller is never rebooted. The expected initial boot ID is checked before work;
set `VAULTREWIND_REMOTE_VM_EXPECTED_BOOT_ID` explicitly for a newly authorized VM.

Prepare the reviewed bundle and copy it, and the separate hook, to the VM using
pinned SSH host checking. The exact setup used for the recorded run was:

```
.venv/bin/python helper/build_bundle.py helper/.vm-bundle
ssh -p 22229 -i .runtime/vm/id_ed25519 \
  -o UserKnownHostsFile=.runtime/vm/known_hosts -o StrictHostKeyChecking=yes \
  root@127.0.0.1 'mkdir -p /root/vrw-vm-drill/bundle'
scp -P 22229 -i .runtime/vm/id_ed25519 \
  -o UserKnownHostsFile=.runtime/vm/known_hosts -o StrictHostKeyChecking=yes \
  helper/.vm-bundle/* root@127.0.0.1:/root/vrw-vm-drill/bundle/
scp -P 22229 -i .runtime/vm/id_ed25519 \
  -o UserKnownHostsFile=.runtime/vm/known_hosts -o StrictHostKeyChecking=yes \
  helper/fixtures/vm_fault.py root@127.0.0.1:/root/vrw-vm-drill/vm_fault.py
ssh -p 22229 -i .runtime/vm/id_ed25519 \
  -o UserKnownHostsFile=.runtime/vm/known_hosts -o StrictHostKeyChecking=yes \
  root@127.0.0.1 'docker pull ghcr.io/dani-garcia/vaultwarden:1.37.4'
VAULTREWIND_REMOTE_VM_TEST=1 .venv/bin/pytest tests/unit/test_remote_vm.py -q
```

The test asserts the exact image content ID after pulling. It installs the
production helper/units through the verified installer. Normal requests, archive
transfer and staging use the real `SSHRemote` adapter. The separate test script
pauses after source stop, after the first durable old-generation rename, and after
final start. Only the SSH-22229 VM receives `systemctl reboot`.

After each reboot, the harness reads the journal and Docker state without calling
`status` or `recover`; therefore the observed recovery must come from the enabled
boot reconciler. Before destructive restore switching, it exports the actual safety
snapshot, commits/verifies it in an encrypted local restic repository and fsyncs a
synthetic pin ledger. This verifies the helper/storage durability boundary, not
the controller API's database pin workflow. The post-activation write sentinel is
synthetic generation content, not an authenticated user's vault operation.

Evidence is written incrementally to `docs/evidence/remote-vm.json`. Private local
staging lives under `helper/.vm-drill`, and the VM's synthetic data and journals
remain available for inspection. They must not be committed. Preserve evidence
before discarding the disposable VM and local staging. Re-run on a fresh VM,
not by overwriting an ambiguous interrupted transaction. No fault hook is enabled
through the production policy or protocol.

Two further empty targets can be prepared on the already tested VM using
`helper/fixtures/prepare_vm_targets.py` and `vm_targets.py`. This admin-only fixture
asserts the preserved VM boot identity, creates a separate restricted operational
SSH key/account and distinct empty bind roots/internal networks, retains every
existing policy entry/journal, and installs the newly reviewed bundle. It refuses
to overwrite an existing enrollment file or armed operation. The private output
`.runtime/vm/controller-enrollment.json` is mode 0600 and includes credentials;
never print, log, commit or publish it. Parent API integration consumes this file.
The public target IDs and verification results are in `docs/REMOTE-CONTRACT.md`.

Daemon outage regression (explicit SSH-22229 authorization required):

```bash
VAULTREWIND_REMOTE_VM_DOCKER_TEST=1 .venv/bin/pytest tests/unit/test_remote_vm_docker.py -x -q
```

This test creates a separate source and temporary enrollment while preserving the
existing guest policy/journal hashes. It installs the production bundle, uses a
separate test-only subclass to SIGKILL the capture helper after graceful source
stop, and stops **guest** docker.service plus docker.socket. The socket is stopped
to prevent socket activation during probes. It verifies the same watchdog PID
survives beyond the deadline while recovery remains pending, starts guest Docker,
and waits for independent recovery without controller status/recover commands.
Successful teardown removes only its own source/data/network/staging, restores the
original policy under the new bundle, and verifies the old container states,
synthetic post-activation sentinels and exact old journal hashes. The new disarmed
journal is retained as evidence. The controller Docker daemon is never stopped.

Evidence: `docs/evidence/remote-vm-docker.json`. Runtime bundle: `helper/.daemon-bundle`
(git-ignored). The fixed guest fixture directory refuses to overwrite an earlier
run; archive that directory only after confirming its journal is safely disarmed
and its test resource cleanup succeeded. This test does not reboot the VM and
must not overlap another VM operation.

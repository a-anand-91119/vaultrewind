"""AC23 opt-in reboot drill for the explicitly prepared QEMU VM on SSH 22229.

Never reboots the controller. The port, marker, known-hosts file and initial boot
identity gate this harness. Test hooks are uploaded separately from the production
helper and are absent from its zipapp.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import secrets
import subprocess
import time
import uuid
from pathlib import Path

import pytest

from vaultrewind import core
from vaultrewind.remote.helper import utc
from vaultrewind.remote.journal import atomic_json
from vaultrewind.remote.protocol import canonical
from vaultrewind.remote.ssh import SSHRemote
from vaultrewind.storage.restic import RepositoryConfig, ResticRepository

ROOT = Path(__file__).resolve().parents[2]
INITIAL_BOOT = os.environ.get("VAULTREWIND_REMOTE_VM_EXPECTED_BOOT_ID", "ad62847b-7e44-4dff-b963-f0b25bff5533")
IMAGE = "sha256:b4312ccf9634e3b5e7044a90ca13169c78b2627c648b81092f0523a5d07fd7f6"
SSH = ["ssh", "-p", "22229", "-i", str(ROOT / ".runtime/vm/id_ed25519"),
       "-o", "UserKnownHostsFile=" + str(ROOT / ".runtime/vm/known_hosts"),
       "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=5", "-o", "BatchMode=yes", "root@127.0.0.1"]
REMOTE = "python3 /root/vrw-vm-drill/vm_fault.py "


def admin(command, payload=None, *, timeout=300, check=True):
    result = subprocess.run([*SSH, command], input=payload, capture_output=True, timeout=timeout, check=False)
    if check and result.returncode:
        raise AssertionError("Disposable VM command failed: " + result.stderr.decode(errors="replace")[-1500:])
    return result


def remote_json(command, *, timeout=30):
    return json.loads(admin(command, timeout=timeout).stdout)


def rpc(client, verb, iid, op, token, payload=None):
    return asyncio.run(client.request(verb, iid, op, token, payload))


def start_fault(kind, verb, iid, op, token, payload):
    request = {"schema_version": 1, "verb": verb, "instance_id": iid, "operation_id": op,
               "idempotency_key": verb + ":" + payload.get("phase", "default"), "fencing_token": token, "payload": payload}
    child = subprocess.Popen([*SSH, REMOTE + "fault-" + kind], stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    child.stdin.write(canonical(request) + b"\n")
    child.stdin.close()
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        trigger = remote_json(REMOTE + "trigger")
        if trigger.get("operation_id") == op:
            return child, trigger
        if child.poll() is not None:
            raise AssertionError("Test hook exited before the requested boundary: " + child.stderr.read().decode(errors="replace")[-1500:])
        time.sleep(2)
    child.terminate()
    raise AssertionError("The requested VM fault boundary was not reached")


def reboot_and_observe(op, before, expected):
    # The reboot command only ever travels through the hard-coded SSH 22229 target.
    admin("test -f /root/vaultrewind-fixture-ready && systemctl reboot", timeout=15, check=False)
    deadline = time.monotonic() + 240
    last = None
    while time.monotonic() < deadline:
        try:
            result = admin(REMOTE + "inspect " + op, timeout=15, check=False)
            if result.returncode == 0:
                last = json.loads(result.stdout)
                if last["boot_id"] != before and last["journal"]["phase"] == expected:
                    assert last["running"] is True
                    return last
        except (subprocess.TimeoutExpired, ValueError):
            pass
        time.sleep(3)
    raise AssertionError("Independent boot reconciliation did not reach its expected state: " + json.dumps(last))


@pytest.mark.systemd
@pytest.mark.skipif(os.environ.get("VAULTREWIND_REMOTE_VM_TEST") != "1", reason="explicit disposable QEMU VM reboot test")
def test_ac23_real_vm_reboot_capture_and_restore_boundaries():
    evidence_path = ROOT / "docs/evidence/remote-vm.json"
    work = ROOT / "helper/.vm-drill"
    work.mkdir(mode=0o700, exist_ok=True)
    start = time.monotonic()
    boot = admin("test -f /root/vaultrewind-fixture-ready && cat /proc/sys/kernel/random/boot_id", timeout=15).stdout.decode().strip()
    # On a deliberate rerun the owner must refresh the expected boot identity in this fixture.
    assert boot == INITIAL_BOOT, "VM initial identity differs from the explicitly authorized fixture"
    if (work / "spec.json").exists():
        spec = json.loads((work / "spec.json").read_bytes())
        iid = spec["instance_id"]
        setup = remote_json("cat /root/vrw-vm-drill/spec.json", timeout=30)
        assert setup["instance_id"] == iid and setup.get("source_id"), "Original VM setup has not completed; do not duplicate it"
    else:
        iid = str(uuid.uuid4())
        spec = {"instance_id": iid, "image_id": IMAGE}
        atomic_json(work / "spec.json", spec)
        admin("cat > /root/vrw-vm-drill/spec.json", canonical(spec))
        setup = remote_json(REMOTE + "setup", timeout=600)
    bundle_hash = hashlib.sha256((ROOT / "helper/.vm-bundle/helper.pyz").read_bytes()).hexdigest()
    admin("id vrwfixture >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin vrwfixture", timeout=15)
    admin("python3 /root/vrw-vm-drill/bundle/install.py --policy /root/vrw-vm-drill/policy.json --ssh-user vrwfixture --bundle-sha256 " + bundle_hash, timeout=120)
    known_lines = (ROOT / ".runtime/vm/known_hosts").read_text().splitlines()
    host_line = next(line for line in known_lines if " ssh-ed25519 " in line and "22229" in line)
    host_key = " ".join(host_line.split()[1:3])
    client = SSHRemote({"endpoint": "127.0.0.1", "port": 22229, "username": "root", "host_public_key": host_key,
                        "private_key": (ROOT / ".runtime/vm/id_ed25519").read_text(), "request_timeout": 1800})
    evidence = {"fixture": "authorized disposable QEMU VM, SSH localhost:22229", "started_at": utc(),
                "helper_bundle_sha256": bundle_hash, "image_id": IMAGE, "source_instance_uuid": iid,
                "initial_boot_id": boot, "source_container_id": setup["source_id"], "cases": [], "status": "running"}
    atomic_json(evidence_path, evidence)
    capture_op = str(uuid.uuid4())
    capture = rpc(client, "capture", iid, capture_op, 1, {"snapshot_uuid": str(uuid.uuid4()), "controller_time": utc()})
    assert capture["phase"] == "captured"
    archive = work / "snapshot.tar"
    asyncio.run(client.export(iid, capture_op, 1, archive))
    core.safe_extract(archive, work / "snapshot")
    core.verify_snapshot(work / "snapshot", capture["manifest_hash"])
    evidence["initial_capture"] = {"operation_id": capture_op, "snapshot_uuid": capture["snapshot_uuid"], "manifest_hash": capture["manifest_hash"]}
    atomic_json(evidence_path, evidence)

    interrupted_capture = str(uuid.uuid4())
    process, trigger = start_fault("capture", "capture", iid, interrupted_capture, 2,
                                   {"snapshot_uuid": str(uuid.uuid4()), "controller_time": utc()})
    paused = remote_json(REMOTE + "inspect " + interrupted_capture)
    assert paused["journal"]["phase"] == "quiescing" and not paused["running"]
    after = reboot_and_observe(interrupted_capture, boot, "failed_safe")
    process.wait(timeout=30)
    evidence["cases"].append({"case": "reboot_after_capture_stop", "trigger": trigger, "before_boot_id": boot, "after": after,
                              "independent_boot_reconciler": True, "passed": True})
    boot = after["boot_id"]
    atomic_json(evidence_path, evidence)

    admin(REMOTE + "later-write")
    password = secrets.token_urlsafe(40)
    repository_id = str(uuid.uuid4())
    repository = ResticRepository(RepositoryConfig(str(work / "safety-repository"), password, instance_uuid=iid,
                                                  runtime_dir=work / "restic-runtime"))
    repository.initialize()
    for fence, fault_kind, expected_phase in ((3, "switch", "rolled_back"), (4, "activate", "complete")):
        op = str(uuid.uuid4())
        discovery = rpc(client, "discover", iid, op, fence)
        staged = asyncio.run(client.upload_restore(iid, op, fence, archive,
                             {"manifest_hash": capture["manifest_hash"], "expected_fingerprint": discovery["fingerprint"], "controller_time": utc()}))
        assert staged["phase"] == "staged"
        safety = rpc(client, "commit_restore", iid, op, fence, {"phase": "prepare_safety"})
        safety_archive = work / (op + "-safety.tar")
        asyncio.run(client.export(iid, op, fence, safety_archive, {"kind": "safety"}))
        safety_root = work / (op + "-safety")
        core.safe_extract(safety_archive, safety_root)
        verified = core.verify_snapshot(safety_root, safety["safety_manifest_hash"])
        committed = repository.commit(safety_root, safety["safety_snapshot_uuid"], verified["manifest"]["captured_at"])
        assert committed["stored_copy_verified"]
        pin = {"snapshot_uuid": safety["safety_snapshot_uuid"], "manifest_hash": safety["safety_manifest_hash"],
               "restic_snapshot_id": committed["restic_snapshot_id"], "repository_id": repository_id,
               "durable": True, "encrypted": True, "pinned": True, "stored_copy_verified": True}
        # Explicit synthetic retention pin ledger; no automatic retention acts on this repository.
        atomic_json(work / (op + "-safety-pin.json"), pin)
        switch_payload = {"phase": "switch_validate", "safety_ack": pin}
        if fault_kind == "switch":
            process, trigger = start_fault("switch", "commit_restore", iid, op, fence, switch_payload)
        else:
            result = rpc(client, "commit_restore", iid, op, fence, switch_payload)
            assert result["phase"] == "candidate_validated"
            process, trigger = start_fault("activate", "commit_restore", iid, op, fence, {"phase": "activate"})
        paused = remote_json(REMOTE + "inspect " + op)
        assert paused["journal"]["phase"] == ("switching" if fault_kind == "switch" else "activation_started")
        after = reboot_and_observe(op, boot, expected_phase)
        process.wait(timeout=30)
        if fault_kind == "switch":
            assert after["later_original_content"] and after["source_running"]
        else:
            assert after["post_activation_write"] and not after["later_original_content"]
            assert not after["source_running"]
        evidence["cases"].append({"case": "reboot_during_pre_activation_switch" if fault_kind == "switch" else "reboot_after_public_start",
                                  "trigger": trigger, "before_boot_id": boot, "after": after,
                                  "safety_restic_snapshot_id": committed["restic_snapshot_id"], "safety_stored_copy_verified": True,
                                  "pinning": "fsynced synthetic test pin ledger; controller API pin workflow is separate",
                                  "independent_boot_reconciler": True, "passed": True})
        boot = after["boot_id"]
        atomic_json(evidence_path, evidence)
    evidence.update({"status": "passed", "finished_at": utc(), "elapsed_seconds": round(time.monotonic() - start, 3),
                     "scope": "Real production helper/systemd boot reconciliation; fault hooks are external test-only subclasses. Synthetic generation sentinel represents post-activation writes, not an authenticated user login."})
    atomic_json(evidence_path, evidence)

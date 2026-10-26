"""Opt-in daemon stop/start ONLY on the explicitly authorized disposable SSH-22229 VM."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from uuid import uuid4

import pytest

from vaultrewind.remote.journal import atomic_json

ROOT = Path(__file__).resolve().parents[2]
SSH = ['ssh', '-p', '22229', '-i', str(ROOT / '.runtime/vm/id_ed25519'),
       '-o', 'UserKnownHostsFile=' + str(ROOT / '.runtime/vm/known_hosts'),
       '-o', 'StrictHostKeyChecking=yes', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', 'root@127.0.0.1']
BASE = '/root/vrw-daemon-drill'
COMMAND = '/usr/bin/python3 -I ' + BASE + '/vm_daemon.py '


def admin(command, payload=None, timeout=240, check=True):
    result = subprocess.run([*SSH, command], input=payload, capture_output=True, timeout=timeout, check=False)
    if check and result.returncode:
        raise AssertionError('VM administrative test command failed; private stderr withheld')
    return result


def observe():
    return json.loads(admin(COMMAND + 'observe', timeout=45).stdout)


@pytest.mark.systemd
@pytest.mark.skipif(os.environ.get('VAULTREWIND_REMOTE_VM_DOCKER_TEST') != '1', reason='explicit SSH-22229 Docker daemon outage authorization required')
def test_watchdog_survives_daemon_outage_past_deadline_and_recovers_without_controller():
    evidence = {'status': 'running', 'fixture': 'authorized disposable SSH-22229 VM only', 'rebooted': False}
    evidence_path = ROOT / 'docs/evidence/remote-vm-docker.json'
    bundle = ROOT / 'helper/.daemon-bundle'
    start = time.monotonic()
    subprocess.run([sys.executable, str(ROOT / 'helper/build_bundle.py'), str(bundle)], check=True, capture_output=True)
    checksum = hashlib.sha256((bundle / 'helper.pyz').read_bytes()).hexdigest()
    evidence['helper_bundle_sha256'] = checksum
    boot = admin('test -f /root/vaultrewind-fixture-ready && cat /proc/sys/kernel/random/boot_id').stdout.decode().strip()
    assert boot == 'eaa17f94-6d57-4a9d-bc12-d3c512411ce9'
    spec = {'instance_id': str(uuid4()), 'operation_id': str(uuid4()), 'snapshot_id': str(uuid4()), 'boot_id': boot,
            'image_id': 'sha256:b4312ccf9634e3b5e7044a90ca13169c78b2627c648b81092f0523a5d07fd7f6'}
    evidence.update(instance_id=spec['instance_id'], operation_id=spec['operation_id'], initial_boot_id=boot)
    atomic_json(evidence_path, evidence)
    # Fresh fixture directory: never overwrite/reuse an ambiguous previous test.
    admin('install -d -m 700 ' + BASE + '/bundle')
    admin('test ! -f ' + BASE + '/original-policy.json')
    admin('cat > ' + BASE + '/spec.json', json.dumps(spec).encode())
    admin('cat > ' + BASE + '/vm_daemon.py', (ROOT / 'helper/fixtures/vm_daemon.py').read_bytes())
    for name in ('helper.pyz', 'install.py', 'checksums.json', 'vaultrewind-watchdog@.service', 'vaultrewind-reconcile.service'):
        admin('cat > ' + BASE + '/bundle/' + name, (bundle / name).read_bytes())
    setup = json.loads(admin(COMMAND + 'setup', timeout=300).stdout)
    evidence['setup'] = setup
    atomic_json(evidence_path, evidence)
    install = '/usr/bin/python3 -I ' + BASE + '/bundle/install.py --ssh-user vrwcontroller --bundle-sha256 ' + checksum + ' --policy '
    admin(install + BASE + '/test-policy.json')
    evidence['production_helper_installed'] = True
    atomic_json(evidence_path, evidence)
    # Separate TEST-ONLY subclass dies after the real graceful stop. Its SSH channel
    # disappears too; no controller status/cancel/recover call can produce recovery.
    child = subprocess.Popen([*SSH, COMMAND + 'capture'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    down = False
    try:
        assert child.wait(timeout=360) != 0
        before = observe()
        assert before['journal']['phase'] == 'quiescing' and before['watchdog_armed']
        assert before['source_running'] is False
        assert 'ActiveState=active' in before['watchdog']
        evidence['before_outage'] = before
        atomic_json(evidence_path, evidence)
        down = True
        admin(COMMAND + 'outage', timeout=180)
        limit = time.monotonic() + 210
        while time.monotonic() < limit:
            waiting = observe()
            assert 'ActiveState=active' in waiting['watchdog'], 'Docker stop stopped the watchdog'
            assert 'ActiveState=inactive' in waiting['docker']
            assert 'ActiveState=inactive' in waiting['socket']
            if waiting['now'] > waiting['journal']['deadline'] + 5 and waiting['journal']['phase'] == 'source_recovery_failed':
                break
            time.sleep(2)
        else:
            pytest.fail('No truthful pending recovery observed beyond the deadline')
        assert waiting['watchdog_armed'] and not waiting.get('source_running', False)
        assert waiting['watchdog'].split('MainPID=')[1].splitlines()[0] == before['watchdog'].split('MainPID=')[1].splitlines()[0]
        evidence['past_deadline_docker_down'] = waiting
        atomic_json(evidence_path, evidence)
        admin(COMMAND + 'start', timeout=180)
        down = False
        limit = time.monotonic() + 240
        while time.monotonic() < limit:
            after = observe()
            if after['journal']['phase'] == 'failed_safe' and after['watchdog_armed'] is False:
                break
            time.sleep(2)
        else:
            pytest.fail('Independent watchdog did not recover after Docker returned')
        assert after['source_running'] and after['boot_id'] == boot
        evidence['after_daemon_start'] = after
        evidence['verification'] = json.loads(admin(COMMAND + 'cleanup', timeout=180).stdout)
        admin(install + BASE + '/original-policy.json')
        final = json.loads(admin("/usr/bin/python3 -I -c \"import json,pathlib; p=pathlib.Path('/var/lib/vaultrewind-helper/journals'); print(json.dumps({'armed':sum(bool(json.loads(f.read_bytes()).get('watchdog_armed')) for f in p.glob('*.json')),'boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()}))\"").stdout)
        assert final['armed'] == 0 and final['boot_id'] == boot
        evidence.update(status='passed', final_vm_state=final, original_policy_restored=True,
                        controller_recovery_invoked=False, elapsed_seconds=round(time.monotonic() - start, 2))
        atomic_json(evidence_path, evidence)
    finally:
        if down:
            admin(COMMAND + 'start', timeout=180)
        if child.poll() is None:
            child.kill()
            child.wait(timeout=15)

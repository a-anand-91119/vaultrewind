"""TEST ONLY controller-side provisioning for the already booted disposable VM."""
import asyncio
import hashlib
import json
import os
import subprocess
import uuid
from pathlib import Path

from vaultrewind.remote.helper import utc
from vaultrewind.remote.ssh import SSHRemote

ROOT = Path(__file__).resolve().parents[2]
VM = ROOT / '.runtime/vm'
SSH = ['ssh', '-p', '22229', '-i', str(VM / 'id_ed25519'), '-o', 'UserKnownHostsFile=' + str(VM / 'known_hosts'), '-o', 'StrictHostKeyChecking=yes', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', 'root@127.0.0.1']


def admin(command, payload=None, timeout=180):
    result = subprocess.run([*SSH, command], input=payload, capture_output=True, timeout=timeout, check=False)
    if result.returncode:
        raise RuntimeError('Disposable VM administrative command failed: ' + result.stderr.decode(errors='replace')[-1000:])
    return result.stdout


def main():
    os.umask(0o077)
    output = VM / 'controller-enrollment.json'
    if output.exists():
        raise RuntimeError('Enrollment already prepared; preserve its identifiers and credentials')
    boot = admin('test -f /root/vaultrewind-fixture-ready && cat /proc/sys/kernel/random/boot_id').decode().strip()
    assert boot == 'eaa17f94-6d57-4a9d-bc12-d3c512411ce9', 'Review changed disposable VM identity'
    key = VM / 'controller_id_ed25519'
    if not key.exists():
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'vaultrewind-disposable-vm-operational', '-f', str(key)], check=True)
    spec_path = VM / 'controller-target-spec.json'
    if spec_path.exists():
        spec = json.loads(spec_path.read_bytes())
    else:
        spec = {'boot_id': boot, 'alternate_id': str(uuid.uuid4()), 'runner_id': str(uuid.uuid4()),
                'image_id': 'sha256:b4312ccf9634e3b5e7044a90ca13169c78b2627c648b81092f0523a5d07fd7f6',
                'public_key': key.with_suffix('.pub').read_text()}
        spec_path.write_text(json.dumps(spec))
    admin('install -d -m 700 /root/vrw-vm-drill/api-bundle')
    bundle = ROOT / 'helper/.api-bundle'
    for name in ('helper.pyz', 'install.py', 'checksums.json', 'vaultrewind-watchdog@.service', 'vaultrewind-reconcile.service'):
        admin('cat > /root/vrw-vm-drill/api-bundle/' + name, (bundle / name).read_bytes())
    admin('cat > /root/vrw-vm-drill/vm_targets.py', (ROOT / 'helper/fixtures/vm_targets.py').read_bytes())
    result = json.loads(admin('python3 /root/vrw-vm-drill/vm_targets.py', json.dumps(spec).encode(), timeout=240))
    checksum = hashlib.sha256((bundle / 'helper.pyz').read_bytes()).hexdigest()
    admin('python3 /root/vrw-vm-drill/api-bundle/install.py --policy /root/vrw-vm-drill/api-policy.json --ssh-user vrwcontroller --bundle-sha256 ' + checksum)
    host_line = next(line for line in (VM / 'known_hosts').read_text().splitlines() if ' ssh-ed25519 ' in line and '22229' in line)
    host_key = ' '.join(host_line.split()[1:3])
    operational = {'endpoint': '127.0.0.1', 'port': 22229, 'username': 'vrwcontroller', 'host_public_key': host_key, 'private_key': key.read_text(), 'request_timeout': 2400}
    client = SSHRemote(operational)
    checks = {}
    for kind, target in result['targets'].items():
        iid = target['instance_id']
        checks[kind] = asyncio.run(client.request('preflight', iid, str(uuid.uuid4()), 10, {'controller_time': utc()}))
        assert checks[kind]['empty_target'] and checks[kind]['recovery_verified']
    record = {'synthetic_only': True, 'boot_id': boot, 'operational': operational,
              'admin': {**operational, 'username': 'root', 'private_key': (VM / 'id_ed25519').read_text()},
              'host_create': {'name': 'Disposable QEMU recovery targets', **{k: v for k, v in operational.items() if k != 'request_timeout'},
                              'activation_credential': {'username': 'root', 'private_key': (VM / 'id_ed25519').read_text()}},
              'policy': result['policy'], 'targets': result['targets'], 'preflight': checks, 'helper_bundle_sha256': checksum,
              'bundle_directory': str(bundle), 'alternate_id': spec['alternate_id'], 'runner_id': spec['runner_id']}
    output.write_text(json.dumps(record, indent=2) + '\n')
    output.chmod(0o600)
    print(json.dumps({'ready': True, 'enrollment_file': str(output), 'mode': oct(output.stat().st_mode & 0o777),
                      'alternate_id': spec['alternate_id'], 'runner_id': spec['runner_id'], 'helper_bundle_sha256': checksum}))


if __name__ == '__main__':
    main()

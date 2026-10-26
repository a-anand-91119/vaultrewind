"""TEST ONLY: prepare empty synthetic API targets on the authorized SSH-22229 VM.

Executed as root over that VM's administrative SSH connection with a JSON spec on
stdin. Preserves all existing policy entries, journals, data and running containers.
"""
import json
import os
import pwd
import subprocess
import sys
import uuid
from pathlib import Path


def main():
    assert os.geteuid() == 0 and Path('/root/vaultrewind-fixture-ready').is_file()
    spec = json.load(sys.stdin)
    assert Path('/proc/sys/kernel/random/boot_id').read_text().strip() == spec['boot_id']
    base = Path('/root/vrw-vm-drill')
    sys.path.insert(0, str(base / 'api-bundle/helper.pyz'))
    from vaultrewind.remote.docker import Docker
    from vaultrewind.remote.journal import atomic_json
    from vaultrewind.remote.policy import Policy
    policy = Policy.load()
    for path in (policy.state_root / 'journals').glob('*.json'):
        assert not json.loads(path.read_bytes()).get('watchdog_armed'), 'Preserve any armed operation'
    docker = Docker()
    assert docker.image(spec['image_id'])['Id'] == spec['image_id']
    username = 'vrwcontroller'
    try:
        account = pwd.getpwnam(username)
    except KeyError:
        subprocess.run(['/usr/sbin/useradd', '--system', '--create-home', '--home-dir', '/var/lib/vrwcontroller', '--shell', '/bin/sh', username], check=True)
        account = pwd.getpwnam(username)
    # Public-key-only, locked-password account, constrained at the authorized key.
    public = spec['public_key'].strip()
    assert public.startswith('ssh-ed25519 ') and '\n' not in public
    sshdir = Path(account.pw_dir) / '.ssh'
    sshdir.mkdir(mode=0o700, exist_ok=True)
    authorized = sshdir / 'authorized_keys'
    authorized.write_text('restrict,command="sudo -n -- /usr/local/libexec/vaultrewind-helper" ' + public + '\n')
    authorized.chmod(0o600)
    os.chown(sshdir, account.pw_uid, account.pw_gid)
    os.chown(authorized, account.pw_uid, account.pw_gid)
    targets = {}
    for kind, port in (('alternate', '18100'), ('runner', None), ('recovery', '18102'), ('recovery4', '18103')):
        if kind + '_id' not in spec:
            continue
        iid = spec[kind + '_id']
        assert str(uuid.UUID(iid)) == iid
        name = 'vrw-api-' + kind + '-' + iid
        root = Path('/srv') / name
        root.mkdir(mode=0o700, exist_ok=True)
        data = root / 'data'
        data.mkdir(mode=0o700, exist_ok=True)
        assert not any(data.iterdir()), 'Target must still be empty'
        assert docker.inspect(name, missing=True) is None
        networks = docker.api('GET', '/networks')
        existing = next((item for item in networks if item['Name'] == name), None)
        internal = port is None
        if existing and existing['Internal'] != internal:
            inspected = docker.network(name)
            assert not inspected.get('Containers'), 'Never replace an occupied network'
            assert inspected.get('Labels', {}).get('org.vaultrewind.test') == iid
            # Include stopped containers: attached endpoints alone are insufficient.
            assert not any(docker.inspect(c['Id'])['HostConfig'].get('NetworkMode') in (name, inspected['Id']) for c in docker.containers())
            docker.api('DELETE', '/networks/' + inspected['Id'])
            existing = None
        if not existing:
            docker.api('POST', '/networks/create', {'Name': name, 'Internal': internal, 'Labels': {'org.vaultrewind.test': iid}})
        ports = {'80/tcp': [{'HostIp': '127.0.0.1', 'HostPort': port}]} if port else {}
        target = {'revision': 1, 'container_id': None, 'container_name': name, 'ownership': 'exclusive', 'external_dependencies_ready': True,
                  'allowed_operations': ['discover', 'preflight', 'capture', 'export', 'stage_restore', 'commit_restore', 'rollback', 'status', 'cancel', 'cleanup'],
                  'allowed_image_ids': [spec['image_id']], 'allowed_networks': [name], 'port_bindings': ports,
                  'capture_budget': 1200, 'restore_budget': 1200, 'validation_window': 180, 'free_space_reserve': 32 * 1024**2,
                  'mounts': [{'type': 'bind', 'source': str(data), 'target': '/data', 'read_only': False, 'snapshot_path': 'data'}],
                  'additional_files': {}, 'dependency_inventory': [],
                  'recovery_profile': {'revision': 1, 'network': name, 'port_bindings': ports,
                                       'environment': {'DOMAIN': 'https://vaultrewind-' + kind + '.invalid'}}}
        if iid in policy.value['instances']:
            assert policy.value['instances'][iid] == target, 'Do not replace an existing enrollment'
        policy.value['instances'][iid] = target
        targets[kind] = {'instance_id': iid, 'container_name': name, 'data_path': str(data), 'is_runner': kind == 'runner'}
    Policy(policy.value)
    atomic_json(base / 'api-policy.json', policy.value)
    print(json.dumps({'policy': policy.value, 'targets': targets, 'operational_username': username}))


if __name__ == '__main__':
    main()

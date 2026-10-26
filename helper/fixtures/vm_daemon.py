"""TEST ONLY: daemon outage fixture for the explicitly authorized SSH-22229 VM."""
from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

BASE = Path('/root/vrw-daemon-drill')
sys.path.insert(0, str(BASE / 'bundle/helper.pyz'))

from vaultrewind.core.errors import VaultRewindError
from vaultrewind.remote.docker import Docker
from vaultrewind.remote.helper import Helper, utc
from vaultrewind.remote.journal import Journal, atomic_json
from vaultrewind.remote.policy import Policy
from vaultrewind.remote.protocol import Request
from vaultrewind.remote.recovery import process_identity


def run(*args):
    result = subprocess.run(['/usr/bin/systemctl', *args], capture_output=True, timeout=180, check=False)
    if result.returncode:
        raise RuntimeError('Disposable VM systemd command failed; private stderr withheld')
    return result.stdout.decode().strip()


def assert_guest():
    assert os.geteuid() == 0 and Path('/root/vaultrewind-fixture-ready').is_file()
    spec = json.loads((BASE / 'spec.json').read_bytes())
    assert Path('/proc/sys/kernel/random/boot_id').read_text().strip() == spec['boot_id']
    return spec


def journal_hashes():
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in Path('/var/lib/vaultrewind-helper/journals').glob('*.json')}


def setup():
    spec = assert_guest()
    policy = Policy.load()
    assert not any(json.loads(p.read_bytes()).get('watchdog_armed') for p in (policy.state_root / 'journals').glob('*.json'))
    assert not (BASE / 'original-policy.json').exists(), 'Do not overwrite an unfinished fixture'
    (BASE / 'original-policy.json').write_bytes(Path('/etc/vaultrewind/helper-policy.json').read_bytes())
    old = {'journals': journal_hashes(), 'containers': {}, 'sentinels': {}}
    docker = Docker()
    for item in docker.containers():
        value = docker.inspect(item['Id'])
        old['containers'][item['Id']] = {'running': value['State']['Running'], 'restart': value['HostConfig']['RestartPolicy']}
        for mount in value['Mounts']:
            if mount['Destination'] == '/data':
                sentinel = Path(mount['Source']) / '.post-activation-write'
                if sentinel.is_file():
                    old['sentinels'][str(sentinel)] = hashlib.sha256(sentinel.read_bytes()).hexdigest()
    for iid, item in policy.value['instances'].items():
        if item['container_id'] is None:
            assert not Helper(policy).active(iid), 'An API target became active; coordinate before daemon outage'
            for mount in item['mounts']:
                assert not any(Path(mount['source']).iterdir()), 'API targets must still be empty'
    atomic_json(BASE / 'preserved.json', old)
    iid = spec['instance_id']
    root = Path('/srv') / ('vrw-daemon-' + iid)
    root.mkdir(mode=0o700)
    data = root / 'data'
    data.mkdir(mode=0o700)
    name = 'vrw-daemon-' + iid
    docker.api('POST', '/networks/create', {'Name': name, 'Internal': True, 'Labels': {'org.vaultrewind.test': iid}})
    image = docker.image(spec['image_id'])['Id']
    cid = docker.create(name, {'Image': image, 'Healthcheck': {'Test': ['NONE']}, 'Labels': {'org.vaultrewind.test': iid},
        'HostConfig': {'NetworkMode': name, 'PortBindings': {}, 'RestartPolicy': {'Name': 'unless-stopped'},
                       'Mounts': [{'Type': 'bind', 'Source': str(data), 'Target': '/data'}]}})
    spec.update(container_id=cid, root=str(root), name=name)
    atomic_json(BASE / 'spec.json', spec)
    docker.start(cid)
    docker.health(cid, 90)
    (data / '.synthetic-daemon-sentinel').write_text('preserve this synthetic capture source\n')
    value = copy.deepcopy(policy.value)
    value['instances'][iid] = {'container_id': cid, 'container_name': name, 'ownership': 'exclusive', 'external_dependencies_ready': True,
        'allowed_operations': ['discover', 'preflight', 'capture', 'status', 'cancel', 'cleanup'],
        'allowed_image_ids': [image], 'allowed_networks': [name], 'port_bindings': {},
        'capture_budget': 90, 'validation_window': 90, 'free_space_reserve': 32 * 1024**2,
        'mounts': [{'type': 'bind', 'source': str(data), 'target': '/data', 'snapshot_path': 'data', 'read_only': False}]}
    Policy(value)
    atomic_json(BASE / 'test-policy.json', value)
    print(json.dumps({'ready': True, 'instance_id': iid, 'container_id': cid, 'preserved_journals': len(old['journals'])}))


def capture():
    spec = assert_guest()
    class DiesAfterStop(Docker):
        def stop(self, container, timeout=30):
            super().stop(container, timeout)
            atomic_json(BASE / 'trigger.json', {'operation_id': spec['operation_id'], 'owner': process_identity()})
            os.kill(os.getpid(), signal.SIGKILL)
    service = Helper(Policy.load(), DiesAfterStop())
    service.dispatch(Request(spec['instance_id'], spec['operation_id'], 1, 'daemon-capture', 'capture',
                             {'snapshot_uuid': spec['snapshot_id'], 'controller_time': utc()}))
    raise RuntimeError('The test-only SIGKILL boundary was not reached')


def observe():
    spec = assert_guest()
    journal = Journal(Path('/var/lib/vaultrewind-helper'), spec['operation_id'])
    value = journal.value or {}
    unit = 'vaultrewind-watchdog@' + spec['operation_id'] + '.service'
    def state(name):
        return run('show', name, '--property=ActiveState', '--property=SubState', '--property=MainPID', '--property=NRestarts')
    result = {'journal': journal.public(), 'watchdog_armed': value.get('watchdog_armed'), 'owner': value.get('owner'),
              'watchdog': state(unit), 'docker': state('docker.service'), 'socket': state('docker.socket'),
              'now': time.time(), 'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
    try:
        item = Docker().inspect(spec['container_id'])
        result.update(source_running=item['State']['Running'], restart_policy=item['HostConfig']['RestartPolicy'])
    except VaultRewindError:
        result['docker_available'] = False
    print(json.dumps(result))


def outage():
    spec = assert_guest()
    journal = Journal(Path('/var/lib/vaultrewind-helper'), spec['operation_id']).value
    assert journal['watchdog_armed'] and journal['phase'] == 'quiescing'
    assert (BASE / 'trigger.json').is_file()
    assert not Docker().inspect(spec['container_id'])['State']['Running']
    assert Docker().inspect(spec['container_id'])['HostConfig']['RestartPolicy']['Name'] == 'no'
    # Stopping the socket too prevents a probe from socket-activating the daemon.
    run('stop', 'docker.service', 'docker.socket')
    print(json.dumps({'docker_and_socket_stopped': True}))


def restore_daemon():
    assert_guest()
    run('start', 'docker.socket', 'docker.service')
    print(json.dumps({'docker_started': True}))


def verify_and_cleanup():
    spec = assert_guest()
    service = Helper(Policy.load())
    journal = Journal(service.root, spec['operation_id'])
    assert journal.value['phase'] == 'failed_safe' and not journal.value['watchdog_armed']
    assert journal.value['source_service_outcome'] == 'running'
    assert service.docker.health(spec['container_id'], 90)['internal_http_alive']
    assert (Path(spec['root']) / 'data/.synthetic-daemon-sentinel').read_text() == 'preserve this synthetic capture source\n'
    preserved = json.loads((BASE / 'preserved.json').read_bytes())
    current = journal_hashes()
    assert all(current.get(name) == value for name, value in preserved['journals'].items()), 'Old journals changed'
    for cid, before in preserved['containers'].items():
        found = service.docker.inspect(cid)
        assert found['State']['Running'] == before['running']
        assert found['HostConfig']['RestartPolicy'] == before['restart']
        if before['running']:
            service.docker.health(cid, 90)
    for path, expected in preserved['sentinels'].items():
        assert hashlib.sha256(Path(path).read_bytes()).hexdigest() == expected
    # Own synthetic resources only. Retain the new, disarmed recovery journal as evidence.
    service.dispatch(Request(spec['instance_id'], spec['operation_id'], 1, 'daemon-cleanup', 'cleanup', {'kind': 'staging'}))
    service.docker.stop(spec['container_id'])
    service.docker.remove(spec['container_id'])
    service.docker.api('DELETE', '/networks/' + spec['name'])
    shutil.rmtree(spec['root'])
    print(json.dumps({'source_recovered_independently': True, 'original_journal_hashes_unchanged': True,
                      'old_container_states_preserved': True, 'old_sentinels_preserved': True,
                      'synthetic_resources_removed': True, 'journal': journal.public()}))


if __name__ == '__main__':
    {'setup': setup, 'capture': capture, 'observe': observe, 'outage': outage,
     'start': restore_daemon, 'cleanup': verify_and_cleanup}[sys.argv[1]]()

#!/usr/bin/env python3
"""Prepare/enroll disposable SSH-22229 targets through the real controller API.

Only host activation, read-only discovery and empty-instance registration are
allowed here. No backup, application restore or native service restart occurs.
Private connection data is read from mode-0600 files and never logged.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import shlex
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import asyncssh
import httpx

from vaultrewind.remote.journal import atomic_json
from vaultrewind.server.provisioning import BOOTSTRAP

ROOT = Path(__file__).resolve().parents[1]
VM = ROOT / '.runtime/vm'
CONTROLLER = ROOT / '.runtime/controller'
TERMINAL = {'succeeded', 'failed', 'partial', 'cancelled', 'rolled_back', 'rollback_failed', 'needs_attention'}


class DrillError(Exception):
    """Only sanitized step/code data; never raw SSH stderr or credential objects."""


def private(path):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as source:
        if os.fstat(source.fileno()).st_mode & 0o077:
            raise DrillError('PRIVATE_FILE_MODE')
        return json.load(source)


def admin(command, payload=None):
    ssh = ['ssh', '-p', '22229', '-i', str(VM / 'id_ed25519'),
           '-o', 'UserKnownHostsFile=' + str(VM / 'known_hosts'),
           '-o', 'StrictHostKeyChecking=yes', '-o', 'BatchMode=yes',
           '-o', 'ConnectTimeout=10', 'root@127.0.0.1']
    result = subprocess.run([*ssh, command], input=payload, capture_output=True, timeout=240, check=False)
    if result.returncode:
        raise DrillError('VM_ADMIN_COMMAND_FAILED')
    return result.stdout


async def bootstrap(config):
    start = time.monotonic()
    try:
        async with asyncio.timeout(240), asyncssh.connect(config['endpoint'], port=config['port'], username=config['username'],
                client_keys=[asyncssh.import_private_key(config['private_key'])],
                known_hosts=([asyncssh.import_public_key(config['host_public_key'])], [], []),
                agent_path=None, agent_forwarding=False, config=[], connect_timeout=20, login_timeout=20) as conn:
            result = await conn.run('/usr/bin/python3 -I -c ' + shlex.quote(BOOTSTRAP),
                                    input=b'{"mode":"discover"}', encoding=None, check=False, timeout=180)
            if len(result.stdout) > 16 * 1024**2:
                raise DrillError('DISCOVERY_OUTPUT_LIMIT')
            value = json.loads(result.stdout)
            if result.exit_status or not value.get('ok'):
                raise DrillError('EXACT_BOOTSTRAP_FAILED')
            return value['result'], round(time.monotonic() - start, 2)
    except (OSError, asyncssh.Error, TimeoutError, ValueError):
        raise DrillError('PINNED_ADMIN_BOOTSTRAP_FAILED') from None


def api(client, method, path, body=None, expected=200, key=None):
    headers = {'Idempotency-Key': key or str(uuid4())} if method != 'GET' else {}
    result = client.request(method, '/api/v1' + path, json=body, headers=headers)
    if result.status_code != expected:
        try:
            code = result.json().get('error', {}).get('code', 'HTTP_ERROR')
        except (ValueError, AttributeError):
            code = 'HTTP_ERROR'
        raise DrillError(f'{method} {path}: HTTP {result.status_code} {code}')
    return result.json()


def wait_job(client, accepted, timeout=1200):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            job = api(client, 'GET', '/jobs/' + accepted['job_id'])
        except httpx.TransportError:
            time.sleep(2)
            continue
        state = (job['state'], job.get('phase'))
        if state != last:
            print(json.dumps({'job_id': job['id'], 'state': state[0], 'phase': state[1]}), flush=True)
            last = state
        if job['state'] in TERMINAL:
            if job['state'] != 'succeeded':
                raise DrillError(f"JOB {job['id']}: {job['state']} {job.get('error_code')}")
            return job
        time.sleep(2)
    raise DrillError('JOB_WAIT_TIMEOUT')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--origin', default='http://127.0.0.1:8098')
    parser.add_argument('--new-plan-after-terminal-activation', action='store_true')
    args = parser.parse_args()
    if args.origin != 'http://127.0.0.1:8098':
        raise DrillError('ONLY_AUTHORIZED_NATIVE_API')
    os.umask(0o077)
    state_path = CONTROLLER / 'vm-targets-progress.json'
    state = private(state_path) if state_path.exists() else {}
    enrollment = private(VM / 'controller-enrollment.json')
    if enrollment['admin']['endpoint'] != '127.0.0.1' or enrollment['admin']['port'] != 22229:
        raise DrillError('ONLY_AUTHORIZED_DISPOSABLE_VM')
    host = private(CONTROLLER / 'vm-host.json')
    host_id = host['id']
    evidence_path = ROOT / 'docs/evidence/vm-targets.json'
    evidence = {'synthetic_only': True, 'scope': 'VM host activation, empty-target discovery/enrollment; no application restore',
                'started_at': datetime.now(UTC).isoformat(), 'status': 'running', 'vm_host_id': host_id}
    atomic_json(evidence_path, evidence)
    discovered, elapsed = asyncio.run(bootstrap(enrollment['admin']))
    evidence['admin_bootstrap'] = {'pinned_asyncssh': True, 'fixed_provisioner_command': True, 'passed': True, 'seconds': elapsed}
    atomic_json(evidence_path, evidence)
    if 'recovery' not in enrollment['targets']:
        state.setdefault('recovery_id', str(uuid4()))
        atomic_json(state_path, state)
        spec = {'boot_id': enrollment['boot_id'], 'recovery_id': state['recovery_id'],
                'image_id': enrollment['policy']['instances'][enrollment['alternate_id']]['allowed_image_ids'][0],
                'public_key': (VM / 'controller_id_ed25519.pub').read_text()}
        admin('cat > /root/vrw-vm-drill/vm_targets.py', (ROOT / 'helper/fixtures/vm_targets.py').read_bytes())
        prepared = json.loads(admin('python3 /root/vrw-vm-drill/vm_targets.py', json.dumps(spec).encode()))
        enrollment['policy'] = prepared['policy']
        enrollment['targets'].update(prepared['targets'])
        enrollment['recovery_id'] = state['recovery_id']
        atomic_json(VM / 'controller-enrollment.json', enrollment)
    target = enrollment['targets']['recovery']
    if target['instance_id'] in (enrollment['alternate_id'], enrollment['runner_id']):
        raise DrillError('RECOVERY_TARGET_MUST_BE_DISTINCT')
    if discovered.get('pending_operations'):
        raise DrillError('VM_HAS_PENDING_OPERATION')
    cookies = private(CONTROLLER / 'api-cookies.json')
    with httpx.Client(base_url=args.origin, cookies=cookies, timeout=30,
                      headers={'Origin': args.origin, 'X-CSRF-Token': cookies['vr_csrf']}) as client:
        if args.new_plan_after_terminal_activation and state.get('activate_job') and not state.get('activated'):
            previous = api(client, 'GET', '/jobs/' + state['activate_job']['job_id'])
            if previous['state'] not in TERMINAL or previous['state'] == 'succeeded':
                raise DrillError('PREVIOUS_ACTIVATION_MUST_BE_FAILED_TERMINAL')
            state.setdefault('previous_activation_jobs', []).append(state.pop('activate_job'))
            state.pop('plan_job', None)
            atomic_json(state_path, state)
        if not state.get('activated'):
            previous = state.get('plan_job')
            if previous:
                old = api(client, 'GET', '/jobs/' + previous['job_id'])
                if old['state'] in TERMINAL and old['state'] != 'succeeded':
                    state.pop('plan_job')
            if not state.get('plan_job'):
                key = 'vm-targets-plan-' + str(uuid4())
                state['plan_job'] = api(client, 'POST', f'/hosts/{host_id}/activation-plans',
                                        {'policy': enrollment['policy']}, expected=202, key=key)
                atomic_json(state_path, state)
            plan_job = wait_job(client, state['plan_job'])
            plan = plan_job['result']
            if not state.get('activate_job'):
                state['activate_job'] = api(client, 'POST', f'/hosts/{host_id}/activate',
                    {'plan_id': plan['plan_id'], 'plan_hash': plan['plan_hash']}, expected=202)
                atomic_json(state_path, state)
            activated = wait_job(client, state['activate_job'])
            state['activated'] = activated['state'] == 'succeeded'
            atomic_json(state_path, state)
        evidence['activation'] = {'plan_job_id': state['plan_job']['job_id'], 'job_id': state['activate_job']['job_id'], 'state': 'succeeded'}
        atomic_json(evidence_path, evidence)
        for kind in ('alternate', 'runner'):
            entry = enrollment['targets'][kind]
            name = 'VM synthetic alternate vault' if kind == 'alternate' else 'VM isolated verification runner'
            key = kind + '_discovery_job'
            if key not in state:
                state[key] = api(client, 'POST', f'/hosts/{host_id}/discover', {'instance_id': entry['instance_id']}, expected=202)
                atomic_json(state_path, state)
            job = wait_job(client, state[key])
            result = api(client, 'GET', f"/jobs/{job['id']}/enrollment")
            if not result['ready']:
                raise DrillError('OPERATIONAL_DISCOVERY_NOT_READY')
            existing = client.get('/api/v1/instances/' + entry['instance_id'])
            if existing.status_code == 404:
                registered = api(client, 'POST', '/instances', {'host_id': host_id, 'name': name,
                    'container_id': entry['container_name'], 'configuration': result['configuration'],
                    'is_runner': kind == 'runner'}, expected=201)
            elif existing.status_code == 200:
                registered = existing.json()
            else:
                raise DrillError('INSTANCE_READ_FAILED')
            if registered['id'] != entry['instance_id'] or registered['host_id'] != host_id:
                raise DrillError('INSTANCE_BINDING_MISMATCH')
            state[kind + '_registered'] = True
            state[kind + '_name'] = name
            atomic_json(state_path, state)
            evidence[kind] = {'instance_id': entry['instance_id'], 'name': name, 'discovery_job_id': job['id'],
                              'enrolled': True, 'is_runner': kind == 'runner', 'readiness': registered['readiness'],
                              'source_state': registered['source_health']}
            atomic_json(evidence_path, evidence)
        # The third target belongs to a future independent controller, never native registration.
        existing = client.get('/api/v1/instances/' + target['instance_id'])
        if existing.status_code != 404:
            raise DrillError('RECOVERY_TARGET_ALREADY_NATIVE_ENROLLED')
    installed, _ = asyncio.run(bootstrap(enrollment['admin']))
    if installed['installed_policy'] != enrollment['policy']:
        raise DrillError('INSTALLED_POLICY_DIFFERS_FROM_REVIEWED')
    enrollment['policy'] = installed['installed_policy']
    descriptor = {'host_create': enrollment['host_create'], 'remote_instance_id': target['instance_id'],
                  'name': 'Recovered controller synthetic vault', 'container_id': target['container_name'],
                  'policy': installed['installed_policy']}
    atomic_json(VM / 'controller-loss-target.json', descriptor)
    # Read just before the atomic merge to preserve ROOT's concurrently added fields.
    integration = private(CONTROLLER / 'integration.json')
    integration.update(vm_host_id=host_id, alternate_id=enrollment['alternate_id'], alternate_name=state['alternate_name'],
                       runner_id=enrollment['runner_id'], runner_name=state['runner_name'])
    atomic_json(CONTROLLER / 'integration.json', integration)
    evidence.update(status='passed', finished_at=datetime.now(UTC).isoformat(),
                    recovery_target={'instance_id': target['instance_id'], 'native_enrolled': False, 'loopback_port': 18102,
                                     'descriptor_private_mode': oct((VM / 'controller-loss-target.json').stat().st_mode & 0o777)},
                    installed_policy_instances=len(installed['installed_policy']['instances']),
                    preserved_reboot_journals=True, native_source_operations=False)
    atomic_json(evidence_path, evidence)
    print(json.dumps({'status': 'passed', 'vm_host_id': host_id, 'alternate_id': enrollment['alternate_id'],
                      'runner_id': enrollment['runner_id'], 'recovery_target_id': target['instance_id'],
                      'private_descriptor': '.runtime/vm/controller-loss-target.json'}), flush=True)


if __name__ == '__main__':
    try:
        main()
    except (DrillError, httpx.TransportError) as error:
        reason = str(error) if isinstance(error, DrillError) else 'API_TRANSPORT_FAILED'
        evidence_path = ROOT / 'docs/evidence/vm-targets.json'
        if evidence_path.exists():
            evidence = json.loads(evidence_path.read_bytes())
            evidence.update(status='failed', reason=reason)
            atomic_json(evidence_path, evidence)
        print(json.dumps({'status': 'failed', 'reason': reason}), flush=True)
        raise SystemExit(1) from None

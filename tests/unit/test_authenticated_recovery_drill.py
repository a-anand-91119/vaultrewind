"""Scope, private-channel and lost-response guards for the opt-in client drill."""
import json
import os
from copy import deepcopy
from types import SimpleNamespace
from uuid import uuid4

import pytest

from scripts import prove_authenticated_recovery as drill


def test_default_prepare_cannot_connect_or_create_files(monkeypatch, capsys):
    def forbidden(*args, **kwargs):
        pytest.fail('Default preparation performed I/O')
    monkeypatch.setattr(drill.Drill, '__init__', forbidden)
    monkeypatch.setattr(drill.subprocess, 'run', forbidden)
    monkeypatch.setattr(drill.urllib.request, 'urlopen', forbidden)
    assert drill.main([]) == 0
    assert json.loads(capsys.readouterr().out)['external_io'] is False


@pytest.mark.parametrize('value', [drill.SOURCE_ID, *drill.FORBIDDEN_IDS, '../escape', '',
                                    '11111111-1111-1111-1111-111111111111'])
def test_existing_or_nonrandom_identity_rejected(value):
    with pytest.raises(drill.DrillError):
        drill.scope(str(uuid4()), value)


def test_policy_carries_every_prior_entry_and_host_setting():
    before = {'machine_id': 'm', 'daemon_id': 'd', 'instances': {'old': {'revision': 4}}}
    after = deepcopy(before)
    after['instances']['new'] = {'revision': 1}
    drill.preserved_policy(before, after, 'new')
    for altered in ('remove', 'change', 'host', 'extra'):
        candidate = deepcopy(after)
        if altered == 'remove':
            del candidate['instances']['old']
        elif altered == 'change':
            candidate['instances']['old']['revision'] = 5
        elif altered == 'host':
            candidate['daemon_id'] = 'other'
        else:
            candidate['instances']['unreviewed'] = {}
        with pytest.raises(drill.DrillError, match='EXISTING_POLICY_CHANGED'):
            drill.preserved_policy(before, candidate, 'new')


def test_container_guard_rejects_label_bind_mount_image_and_network_substitution(tmp_path):
    run_id, instance_id = str(uuid4()), str(uuid4())
    paths = {'root': tmp_path, 'name': 'vrw-auth-drill-' + instance_id, 'network': 'private'}
    state = {'run_id': run_id, 'instance_id': instance_id, 'image_id': 'sha256:abc'}
    value = {'Name': '/' + paths['name'], 'Image': state['image_id'],
        'Config': {'Labels': {'vaultrewind.authenticated-recovery': run_id, 'org.vaultrewind.instance': instance_id}},
        'Mounts': [{'Type': 'bind', 'Source': str(tmp_path / 'data'), 'Destination': '/data', 'RW': True}],
        'HostConfig': {'PortBindings': {'80/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '18280'}]},
                       'NetworkMode': 'private'}}
    drill.validate_container(value, state, paths)
    variants = []
    for field, replacement in [('Name', '/vr-ssh-source'), ('Image', 'sha256:other')]:
        candidate = deepcopy(value)
        candidate[field] = replacement
        variants.append(candidate)
    candidate = deepcopy(value)
    candidate['Mounts'][0]['Source'] = '/srv/vaultrewind-fixtures/source/data'
    variants.append(candidate)
    candidate = deepcopy(value)
    candidate['Config']['Labels']['vaultrewind.authenticated-recovery'] = str(uuid4())
    variants.append(candidate)
    candidate = deepcopy(value)
    candidate['HostConfig']['PortBindings']['80/tcp'][0]['HostIp'] = '0.0.0.0'
    variants.append(candidate)
    candidate = deepcopy(value)
    candidate['HostConfig']['NetworkMode'] = 'host'
    variants.append(candidate)
    for candidate in variants:
        with pytest.raises(drill.DrillError):
            drill.validate_container(candidate, state, paths)


def test_private_file_permissions_and_symlink_boundary(tmp_path):
    target = tmp_path / 'secret'
    drill.private_write(target, b'private-value')
    assert target.stat().st_mode & 0o777 == 0o600
    assert drill.private_read(target) == b'private-value'
    target.chmod(0o644)
    with pytest.raises(drill.DrillError, match='PRIVATE_INPUT_REQUIRED'):
        drill.private_read(target)
    target.chmod(0o600)
    link = tmp_path / 'link'
    link.symlink_to(target)
    with pytest.raises(drill.DrillError, match='SYMLINK_PATH_REJECTED'):
        drill.private_read(link)


def test_cli_uses_only_new_appdata_password_env_session_env_and_stdin(tmp_path, monkeypatch):
    obj = object.__new__(drill.Drill)
    obj.root = tmp_path
    password, session, payload = 'random-master-secret', 'random-session-secret', b'encoded-item-secret'
    drill.private_write(tmp_path / 'credentials.json', {'password': password})
    monkeypatch.setenv('HOME', '/existing-user-profile')
    monkeypatch.setenv('BW_SESSION', 'prior-session')
    monkeypatch.setenv('BITWARDENCLI_APPDATA_DIR', '/existing-cli-profile')
    monkeypatch.setenv('AWS_SECRET_ACCESS_KEY', 'unrelated-secret')
    calls = []
    monkeypatch.setattr(drill, 'run', lambda args, **kwargs: calls.append((args, kwargs)) or b'{}')
    profile = 'seed-' + uuid4().hex
    obj.cli(profile, 'create', 'item', payload=payload, session=session)
    args, channels = calls[0]
    assert all(secret not in ' '.join(args) for secret in (password, session, payload.decode()))
    assert channels['payload'] == payload
    assert channels['env']['BW_SESSION'] == session
    assert channels['env']['VAULT_DRILL_PASSWORD'] == password
    assert channels['env']['BITWARDENCLI_APPDATA_DIR'] == str(tmp_path / profile)
    assert 'HOME' not in channels['env'] and 'AWS_SECRET_ACCESS_KEY' not in channels['env']
    assert os.environ['HOME'] == '/existing-user-profile'
    with pytest.raises(drill.DrillError, match='SESSION_ARGUMENT_REJECTED'):
        obj.cli(profile, 'status', '--session', session)
    with pytest.raises(drill.DrillError, match='NEW_CLI_PROFILE_REQUIRED'):
        obj.cli('../existing', 'status')
    with pytest.raises(drill.DrillError, match='EXACT_NEW_BW_SERVER_REQUIRED'):
        obj.cli(profile, 'config', 'server', 'https://vault.bitwarden.com')


def test_reconcile_exact_existing_job_and_refuse_ambiguous_or_changed_request():
    rows = [{'id': 'existing-job', 'idempotency_key': 'stable-run-restore', 'request_hash': 'exact'}]
    assert drill.exact_job(rows, 'stable-run-restore', 'exact') == 'existing-job'
    assert drill.exact_job(rows, 'other-key') is None
    with pytest.raises(drill.DrillError, match='RECONCILE_REQUEST_CHANGED'):
        drill.exact_job(rows, 'stable-run-restore', 'different')
    with pytest.raises(drill.DrillError, match='AMBIGUOUS_JOB_IDENTITY'):
        drill.exact_job(rows * 2, 'stable-run-restore')


def test_lost_job_response_reconciles_database_before_posting(monkeypatch):
    obj = object.__new__(drill.Drill)
    obj.instance = str(uuid4())
    run_id = str(uuid4())
    body, path = {'confirmation_token': 'private-token'}, '/restore-plans/plan/execute'
    obj.state = {'run_id': run_id, 'steps': {'restore': {'key': 'auth-drill-' + run_id + '-restore',
        'path': path, 'body_sha256': drill.digest(body), 'attempted': True}}}
    obj.save = lambda: None
    existing = SimpleNamespace(instance_id=obj.instance, id='exact-existing-job', kind='restore',
        idempotency_key=obj.state['steps']['restore']['key'], request_hash='native-request-hash')
    class DB:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def scalars(self, query):
            return [existing]
    obj.sessions = DB
    obj.request = lambda *args, **kwargs: pytest.fail('Blind duplicate mutation')
    obj.wait_job = lambda ident: {'id': ident, 'state': 'succeeded', 'instance_id': obj.instance}
    assert obj.job('restore', path, body)['id'] == 'exact-existing-job'
    assert obj.state['steps']['restore']['job_id'] == 'exact-existing-job'


def test_lost_response_with_no_existing_job_stops_without_new_restore():
    obj = object.__new__(drill.Drill)
    obj.instance = str(uuid4())
    body, path = {}, '/restore-plans/plan/execute'
    obj.state = {'run_id': str(uuid4()), 'steps': {'restore': {'path': path,
        'body_sha256': drill.digest(body), 'attempted': True}}}
    obj.save = lambda: None
    class DB:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def scalars(self, query):
            return []
    obj.sessions = DB
    obj.request = lambda *args, **kwargs: pytest.fail('Blind duplicate mutation')
    with pytest.raises(drill.DrillError, match='LOST_JOB_RESPONSE_REQUIRES_EXACT_RECONCILE'):
        obj.job('restore', path, body)


def test_registration_disables_capture_and_restricts_origin():
    program = drill.browser_registration_program()
    assert 'route.abort()' in program and '127.0.0.1:18443' in program
    assert 'recordVideo' not in program and 'tracing.start' not in program and '.screenshot(' not in program
    assert 'readFileSync(0' in program


def test_activation_failure_reuses_exact_checkpoint_and_never_reenrolls():
    obj = object.__new__(drill.Drill)
    obj.host_id = str(uuid4())
    plan = {'plan_id': str(uuid4()), 'plan_hash': 'a' * 64}
    obj.state = {'activation_plan': plan, 'steps': {'activate': {'attempted': True, 'job_id': str(uuid4())}}}
    obj.helper = lambda: None
    obj.idle = lambda: pytest.fail('A possible activation must reconcile its existing job first')
    obj.enroll = lambda: pytest.fail('Enrollment after unresolved activation')
    calls = []
    def existing_job(stage, path, body):
        calls.append((stage, path, body))
        raise drill.DrillError('JOB_NEEDS_ATTENTION')
    obj.job = existing_job
    for _ in range(2):
        with pytest.raises(drill.DrillError, match='JOB_NEEDS_ATTENTION'):
            obj.activate(plan['plan_id'])
    assert calls[0] == calls[1]
    assert calls[0][2] == plan
    assert not obj.state.get('activated')


def test_failure_history_allowlist_never_serializes_private_diagnostics():
    state = {'run_id': str(uuid4()), 'failures': [{'stage': 'prove', 'code': 'PRIVATE_FAILURE',
              'time': 123, 'output': 'private-session-value'}]}
    result = drill.safe_failures(state)
    assert 'private-session-value' not in json.dumps(result)
    assert result[0]['code'] == 'PRIVATE_FAILURE'
    state['failures'][0]['code'] = 'error: private-session-value'
    with pytest.raises(drill.DrillError, match='FAILURE_HISTORY_SECRET_BOUNDARY'):
        drill.safe_failures(state)


def test_version_probe_environment_also_excludes_default_profile_and_credentials(tmp_path, monkeypatch):
    monkeypatch.setenv('HOME', '/existing-home')
    monkeypatch.setenv('BITWARDENCLI_APPDATA_DIR', '/existing-cli-profile')
    monkeypatch.setenv('BW_SESSION', 'prior-session')
    monkeypatch.setenv('VAULT_DRILL_PASSWORD', 'prior-password')
    env = drill.client_environment(tmp_path)
    assert env['BITWARDENCLI_APPDATA_DIR'] == str(tmp_path)
    assert not {'HOME', 'BW_SESSION', 'VAULT_DRILL_PASSWORD'} & env.keys()
    assert env['BW_DISABLE_UPDATE_CHECK'] == 'true'

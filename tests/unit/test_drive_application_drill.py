"""Pure synthetic proofs: no private fixtures, provider, SQL server, SSH or Docker."""
from __future__ import annotations

import builtins
import copy
import hashlib
import io
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import urllib.request
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import pytest

from scripts import prove_drive_application_readback as drill
from vaultrewind.core.manifest import canonical_json, create_manifest, manifest_hash, sha256_file
from vaultrewind.remote.overlays import apply_environment


def uid(number):
    return str(UUID(int=number, version=4))


DEST, RUN, JOB, SNAPSHOT, CLOUD, LOCAL, REPO, LOCAL_REPO, HOST, SOURCE_HOST, PLAN = map(uid, range(1, 12))
HASH = 'a' * 64
IMAGE = 'sha256:' + 'b' * 64


def arguments(*extra):
    return drill.parse_args(['--destination-id', DEST, '--dedicated-test-account', *extra])


def forbidden(*_args, **_kwargs):
    pytest.fail('A pure test attempted private/external work or evidence mutation.')


def checkpoint():
    cloud = {'complete': True, 'backend': 'drive', 'snapshot_id': SNAPSHOT, 'copy_id': CLOUD,
             'repository_id': REPO, 'restored_bytes_verified': True, 'saved_image_inventory_verified': True,
             'sqlite_integrity': 'ok', 'manifest_hash': HASH, 'whole_file_map_sha256': HASH,
             'file_count': 9, 'logical_bytes': 123}
    return {'version': 1, 'source_id': drill.SOURCE_ID, 'destination_id': DEST, 'run_id': DEST,
            'dedicated_test_account_acknowledged': True, 'snapshot_id': SNAPSHOT,
            'drive_copy_id': CLOUD, 'local_copy_id': LOCAL, 'drive_readback': cloud,
            'local_readback': {**cloud, 'backend': 'local', 'copy_id': LOCAL, 'repository_id': LOCAL_REPO},
            'steps': {'restore': {'job_id': JOB, 'job': {'state': 'succeeded'}}},
            'restore_plan': {'id': PLAN, 'target_id': drill.ALTERNATE_ID, 'copy_id': CLOUD},
            'alternate_restore': {'complete': True, 'job_id': JOB, 'target_id': drill.ALTERNATE_ID,
                                  'selected_drive_copy_id': CLOUD, 'application_started': True,
                                  'source_started_at_and_whole_hash_unchanged': True,
                                  'public_alive_config_200': True},
            'source_before_restore': {'running': True, 'container_id': 'c' * 64,
                                      'started_at': '2026-10-26T00:00:00Z', 'whole_inventory_sha256': HASH}}


def profile_inputs():
    fixture = {'source_id': drill.SOURCE_ID, 'alternate_id': drill.ALTERNATE_ID, 'vm_host_id': HOST}
    profile = {'container_name': drill.TARGET_NAME,
               'mounts': [{'type': 'bind', 'source': drill.TARGET_ROOT, 'target': '/data',
                           'read_only': False, 'snapshot_path': 'data'}],
               'port_bindings': copy.deepcopy(drill.PUBLIC_BINDINGS),
               'recovery_profile': {'port_bindings': copy.deepcopy(drill.PUBLIC_BINDINGS),
                                    'environment': {'DOMAIN': 'https://synthetic-alternate.invalid'}}}
    policy = {'instances': {drill.ALTERNATE_ID: profile}}
    descriptor = {'remote_instance_id': drill.DESCRIPTOR_PROFILE_ID,
                  'policy': {'instances': {drill.DESCRIPTOR_PROFILE_ID: {}}},
                  'host_create': {'endpoint': '127.0.0.1', 'port': 22229, 'host_public_key': 'synthetic-pin',
                                  'activation_credential': {'username': 'root', 'private_key': 'synthetic-key'}}}
    return fixture, policy, descriptor


def catalog():
    result = {key: True for key in (*drill.PUBLIC_FLAGS, 'candidate_validated', 'application_started',
                                    'restored_bytes_verified')}
    result['active_generation'] = JOB
    job = {'id': JOB, 'kind': 'restore', 'state': 'succeeded', 'instance_id': drill.ALTERNATE_ID,
           'target_activation_outcome': 'complete', 'reconcile_required': False, 'fencing_token': 87,
           'result': result, 'request': {'snapshot_id': SNAPSHOT, 'copy_id': CLOUD,
                                        'target_id': drill.ALTERNATE_ID, 'manifest_hash': HASH, 'plan_id': PLAN}}
    cloud = {'id': CLOUD, 'snapshot_id': SNAPSHOT, 'repository_id': REPO, 'state': 'complete',
             'manifest_hash': HASH, 'restic_snapshot_id': 'd' * 64}
    return {'active_jobs': [], 'vm_host_id': HOST, 'remote_instance_id': drill.ALTERNATE_ID, 'job': job,
            'snapshot': {'id': SNAPSHOT, 'instance_id': drill.SOURCE_ID, 'manifest_hash': HASH,
                         'image_id': IMAGE, 'completeness': 'complete'},
            'copy': cloud, 'local_copy': {**cloud, 'id': LOCAL, 'repository_id': LOCAL_REPO},
            'repository': {'id': REPO, 'instance_id': drill.SOURCE_ID, 'destination_id': DEST},
            'local_repository': {'id': LOCAL_REPO, 'instance_id': drill.SOURCE_ID, 'destination_id': RUN},
            'destination': {'id': DEST, 'backend': 'drive', 'archived': False},
            'local_destination': {'id': RUN, 'backend': 'local', 'archived': False},
            'target': {'id': drill.ALTERNATE_ID, 'host_id': HOST, 'container_id': '', 'active_generation': JOB,
                       'is_runner': False, 'archived': False, 'readiness': 'ready'},
            'source': {'id': drill.SOURCE_ID, 'host_id': SOURCE_HOST, 'archived': False},
            'host': {'id': HOST, 'endpoint': '127.0.0.1', 'port': 22229},
            'plan': {'id': PLAN, 'snapshot_id': SNAPSHOT, 'copy_id': CLOUD, 'target_id': drill.ALTERNATE_ID,
                     'manifest_hash': HASH, 'job_id': JOB, 'consumed_at': 'synthetic-consumption'}}


@pytest.mark.parametrize('flags', [[], ['--root-go', drill.RELEASE],
                                  ['--root-go', drill.RELEASE, '--destination-id', DEST,
                                   '--dedicated-test-account']])
def test_preparation_has_no_runtime_reads_imports_clients_or_writes(flags, monkeypatch, capsys):
    original = builtins.__import__

    def guarded_import(name, *args, **kwargs):
        if name.startswith(('vaultrewind', 'sqlalchemy', 'asyncssh', 'httpx', 'scripts.prove_')):
            forbidden()
        return original(name, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(drill, 'ApplicationReadback', forbidden)
        patch.setattr(drill, 'private_read', forbidden)
        patch.setattr(drill, 'write_evidence', forbidden)
        patch.setattr(Path, 'stat', forbidden)
        patch.setattr(os, 'open', forbidden)
        patch.setattr(builtins, '__import__', guarded_import)
        assert drill.main(flags) == 0
    report = json.loads(capsys.readouterr().out)
    assert report['private_files_opened'] == report['network_sql_provider_ssh_docker_calls'] == 0
    assert report['evidence_written'] is report['application_readback_proven'] is False


@pytest.mark.parametrize('field,value', [('execute', False), ('root_go', 'ROOTGO'),
                                      ('dedicated_test_account', False), ('destination_id', None)])
def test_constructor_gate_precedes_every_private_or_external_action(field, value, monkeypatch):
    args = arguments('--execute', '--root-go', drill.RELEASE)
    setattr(args, field, value)
    monkeypatch.setattr(drill, 'private_directory', forbidden)
    monkeypatch.setattr(drill, 'private_read', forbidden)
    with pytest.raises(drill.DrillError, match='PARKED'):
        drill.ApplicationReadback(args)


@pytest.mark.parametrize('value', ['../controller/master', drill.SOURCE_ID.upper(), '{' + DEST + '}',
                                  '00000000-0000-0000-0000-000000000000'])
def test_uuid_guard_cannot_select_a_path_or_noncanonical_scope(value):
    with pytest.raises(Exception) as error:
        drill.identifier(value)
    assert error.type.__name__ == 'ArgumentTypeError'


def test_checkpoint_requires_complete_matching_readbacks_and_alternate():
    state = checkpoint()
    drill.validate_checkpoint(state, DEST, DEST)
    for path, value in [(('drive_readback', 'complete'), False), (('local_readback', 'copy_id'), CLOUD),
                        (('local_readback', 'whole_file_map_sha256'), 'e' * 64),
                        (('alternate_restore', 'target_id'), drill.SOURCE_ID),
                        (('steps', 'restore', 'job_id'), RUN), (('restore_plan', 'copy_id'), LOCAL)]:
        changed = copy.deepcopy(state)
        cursor = changed
        for key in path[:-1]:
            cursor = cursor[key]
        cursor[path[-1]] = value
        with pytest.raises(drill.DrillError):
            drill.validate_checkpoint(changed, DEST, DEST)
    with pytest.raises(drill.DrillError, match='IDENTITY'):
        drill.validate_checkpoint(state, DEST, RUN)


@pytest.mark.parametrize('change', ['primary', 'descriptor-as-target', 'endpoint', 'port', 'binding', 'root',
                                   'extra-overlay'])
def test_fixture_guards_do_not_confuse_admin_descriptor_with_alternate(change):
    fixture, policy, descriptor = profile_inputs()
    drill.validate_fixture(fixture, policy, descriptor)
    profile = policy['instances'][drill.ALTERNATE_ID]
    if change == 'primary':
        fixture['alternate_id'] = drill.SOURCE_ID
    elif change == 'descriptor-as-target':
        descriptor['remote_instance_id'] = drill.ALTERNATE_ID
    elif change in {'endpoint', 'port'}:
        descriptor['host_create'][change] = 'external.invalid' if change == 'endpoint' else 22
    elif change == 'binding':
        profile['recovery_profile']['port_bindings']['80/tcp'][0]['HostPort'] = '18103'
    elif change == 'root':
        profile['mounts'][0]['source'] = '/srv/unapproved/data'
    else:
        profile['recovery_profile']['environment']['ADMIN_TOKEN'] = 'synthetic-only'
    with pytest.raises(drill.DrillError):
        drill.validate_fixture(fixture, policy, descriptor)


@pytest.mark.parametrize('path,value', [
    (('job', 'request', 'copy_id'), LOCAL), (('job', 'request', 'snapshot_id'), RUN),
    (('job', 'request', 'target_id'), drill.SOURCE_ID), (('copy', 'snapshot_id'), RUN),
    (('copy', 'manifest_hash'), 'e' * 64), (('copy', 'state'), 'pending'),
    (('repository', 'instance_id'), drill.ALTERNATE_ID), (('destination', 'id'), RUN),
    (('plan', 'job_id'), RUN), (('target', 'active_generation'), RUN),
    (('job', 'result', 'active_generation'), RUN), (('remote_instance_id',), drill.DESCRIPTOR_PROFILE_ID),
    (('job', 'result', 'public_ports_verified'), False),
    (('job', 'result', 'public_endpoint_verified'), False), (('active_jobs',), [RUN]),
])
def test_current_generation_restore_request_and_copy_cannot_be_rebound(path, value):
    scope = catalog()
    drill.validate_catalog(checkpoint(), DEST, scope)
    cursor = scope
    for key in path[:-1]:
        cursor = cursor[key]
    cursor[path[-1]] = value
    with pytest.raises(drill.DrillError):
        drill.validate_catalog(checkpoint(), DEST, scope)


def test_api_and_helper_need_both_flags_and_the_current_operation_and_fence():
    job = catalog()['job']
    view = copy.deepcopy(job)
    drill.validate_api_job(view, job)
    helper = {'exists': True, 'kind': 'restore', 'phase': 'complete', 'instance_id': drill.ALTERNATE_ID,
              'operation_id': JOB, 'active_generation': JOB, 'fencing_token': 87,
              'candidate_validated': {'application_started': True},
              'public_ports_verified': True, 'public_endpoint_verified': True}
    drill.validate_helper(helper, job)
    for key in drill.PUBLIC_FLAGS:
        with pytest.raises(drill.DrillError):
            drill.validate_api_job({**view, 'result': {**view['result'], key: False}}, job)
    for key, value in [('phase', 'activating'), ('fencing_token', 86), ('active_generation', RUN),
                       ('operation_id', RUN), ('candidate_validated', False),
                       ('public_ports_verified', False), ('public_endpoint_verified', False)]:
        with pytest.raises(drill.DrillError):
            drill.validate_helper({**helper, key: value}, job)


def test_private_fixture_guards_reject_modes_and_symlink_ancestors_without_repair(tmp_path):
    directory = tmp_path / 'private'
    directory.mkdir(mode=0o700)
    secret = directory / 'synthetic-secret'
    secret.write_bytes(b'synthetic-only')
    secret.chmod(0o600)
    assert drill.private_read(secret) == b'synthetic-only'
    secret.chmod(0o644)
    with pytest.raises(drill.DrillError, match='PRIVATE_FILE'):
        drill.private_read(secret)
    assert secret.stat().st_mode & 0o777 == 0o644
    alias = tmp_path / 'alias'
    alias.symlink_to(directory, target_is_directory=True)
    with pytest.raises(drill.DrillError, match='SYMLINK'):
        drill.private_read(alias / secret.name)


@pytest.fixture
def captured(tmp_path, request):
    restored = tmp_path / 'restored'
    restored.mkdir(mode=0o700)
    for name in ('data', 'deployment', 'images'):
        (restored / name).mkdir(mode=0o700)
    data = restored / 'data'
    with sqlite3.connect(data / 'db.sqlite3') as db:
        for table in ('users', 'organizations', 'ciphers'):
            db.execute(f'CREATE TABLE {table}(id TEXT)')
        db.execute('CREATE TABLE attachments(id TEXT,cipher_uuid TEXT)')
        db.execute('CREATE TABLE sends(uuid TEXT,atype INTEGER,data TEXT,deletion_date TEXT)')
        db.execute("INSERT INTO users VALUES ('synthetic-user')")
    if getattr(request, 'param', True):
        (data / 'config.json').write_text(json.dumps({'domain': 'https://source.invalid',
                                                    'admin_token': 'synthetic-only', 'signups_allowed': False}))
        # Distinct from generated mode 0600, to catch accidental loss of preservation.
        (data / 'config.json').chmod(0o640)
    (data / 'attachment').write_bytes(b'synthetic-attachment')
    (data / 'nested').mkdir()
    (data / 'nested/db.sqlite3').write_bytes(b'unknown persistent file with database-like name')
    (restored / 'deployment/recovery.json').write_text('{}')
    image = restored / 'images/vaultwarden.tar'
    image.write_bytes(b'synthetic-saved-image')
    state, scope = checkpoint(), catalog()
    manifest = create_manifest(restored, {'snapshot_uuid': SNAPSHOT, 'instance_uuid': drill.SOURCE_ID,
        'capture_started_at': '2026-10-26T00:00:00Z', 'captured_at': '2026-10-26T00:00:01Z',
        'source_state': 'running', 'image_id': IMAGE, 'image_archive_hash': sha256_file(image),
        'platform': 'linux/amd64', 'deployment_fingerprint': HASH})
    files = {i['path']: i['sha256'] for i in manifest['inventory'] if i['type'] == 'file'}
    for key in ('drive_readback', 'local_readback'):
        state[key].update(manifest_hash=manifest_hash(manifest), file_count=len(files),
                          logical_bytes=sum(i['size'] for i in manifest['inventory'] if i['type'] == 'file'),
                          whole_file_map_sha256=drill.digest(files))
    scope['snapshot']['manifest_hash'] = manifest_hash(manifest)
    return restored, state, scope, profile_inputs()[1]['instances'][drill.ALTERNATE_ID]


def test_payload_uses_verified_saved_bytes_five_tables_and_only_domain_overlay(captured):
    restored, _state, scope, profile = captured
    original = (restored / 'data/config.json').read_bytes()
    payload, proof = drill.build_payload(*captured)
    assert set(payload['rows']) == set(drill.TABLES) and payload['rows']['users'] == 1
    assert 'nested/db.sqlite3' in {i['path'] for i in payload['files']}
    config = json.loads(original)
    config['domain'] = profile['recovery_profile']['environment']['DOMAIN']
    assert payload['config_hash'] == hashlib.sha256(canonical_json(config)).hexdigest()
    assert (restored / 'data/config.json').read_bytes() == original
    assert proof['manifest_hash'] == scope['snapshot']['manifest_hash']
    (restored / 'images/vaultwarden.tar').write_bytes(b'corrupt')
    with pytest.raises(Exception) as error:
        drill.build_payload(*captured)
    assert error.value.code == 'SNAPSHOT_INCOMPLETE'


@pytest.mark.parametrize('captured', [True, pytest.param(False, marks=pytest.mark.skipif(
    os.geteuid() != 0 or os.getegid() != 0, reason='Actual generated root:root fixture requires root execution.'))],
                         indirect=True)
@pytest.mark.parametrize('corruption', [None, 'file', 'config', 'sqlite', 'operation', 'binding', 'mode', 'uid', 'gid'])
def test_shared_readback_checks_real_synthetic_bytes_without_external_calls(
        captured, corruption, monkeypatch, capsys, tmp_path):
    restored, _, _, _ = captured
    payload, _ = drill.build_payload(*captured)
    source_config = restored / 'data/config.json'
    absent = not source_config.exists()
    if absent:
        assert payload['config_hash'] == hashlib.sha256(canonical_json({'domain': payload['domain']})).hexdigest()
        assert payload['config_metadata'] == {'uid': 0, 'gid': 0, 'mode': 0o600}
    # Keep the verified readback pristine; generate a separate synthetic target
    # using the real helper overlay implementation and helper entrypoint umask.
    data = tmp_path / 'target'
    shutil.copytree(restored / 'data', data)
    previous_umask = os.umask(0o077)
    try:
        apply_environment([{'snapshot_path': 'data', 'source': str(data)}], {'DOMAIN': payload['domain']})
    finally:
        os.umask(previous_umask)
    assert source_config.exists() is not absent
    actual_config = data / 'config.json'
    st = actual_config.stat()
    assert {'uid': st.st_uid, 'gid': st.st_gid, 'mode': st.st_mode & 0o7777} == payload['config_metadata']
    # Execute the reused READBACK with real files/SQLite and in-memory Docker/HTTP replies.
    payload['root'] = str(data)
    if corruption == 'config':
        config = json.loads(actual_config.read_bytes())
        config['admin_token'] = 'unexpected-overlay'
        actual_config.write_bytes(canonical_json(config))
    if corruption == 'mode':
        actual_config.chmod(0o644)
    if corruption in {'uid', 'gid'}:
        if os.geteuid() != 0:
            pytest.skip('Synthetic ownership corruption requires root execution.')
        os.chown(actual_config, st.st_uid + 1 if corruption == 'uid' else st.st_uid,
                 st.st_gid + 1 if corruption == 'gid' else st.st_gid)
    if corruption == 'file':
        (data / 'nested/db.sqlite3').write_bytes(b'changed')
    if corruption == 'sqlite':
        with sqlite3.connect(data / 'db.sqlite3') as db:
            db.execute("INSERT INTO users VALUES ('unexpected-user')")
    container = {'Id': 'f' * 64, 'Image': IMAGE, 'State': {'Running': True, 'StartedAt': 'synthetic-start'},
                 'Config': {'Labels': {'org.vaultrewind.instance': drill.ALTERNATE_ID,
                                      'org.vaultrewind.operation': RUN if corruption == 'operation' else JOB}},
                 'Mounts': [{'Destination': '/data', 'Type': 'bind', 'Source': str(data), 'RW': True}],
                 'NetworkSettings': {'Ports': {'80/tcp': payload['bindings']}},
                 'HostConfig': {'PortBindings': payload['all_bindings']}}
    if corruption == 'binding':
        container['NetworkSettings']['Ports'] = {}

    def inspect(command, **kwargs):
        assert command == ['/usr/bin/docker', 'inspect', drill.TARGET_NAME]
        return json.dumps([container]).encode()

    class Response(io.BytesIO):
        status = 200

    def get(url, **kwargs):
        assert url in {'http://127.0.0.1:18100/alive', 'http://127.0.0.1:18100/api/config'}
        return Response(json.dumps({'version': 'synthetic', 'environment': {'api': payload['domain'] + '/api'}}).encode())

    monkeypatch.setattr(subprocess, 'check_output', inspect)
    monkeypatch.setattr(subprocess, 'run', forbidden)
    monkeypatch.setattr(urllib.request, 'urlopen', get)
    monkeypatch.setattr(sys, 'stdin', io.StringIO(json.dumps(payload)))
    program = compile(drill.readback_program(), '<synthetic-readback>', 'exec')
    if corruption:
        with pytest.raises((AssertionError, KeyError)):
            exec(program, {})  # noqa: S102 - execute the fixed production readback against synthetic files.
    else:
        exec(program, {})  # noqa: S102 - execute the fixed production readback against synthetic files.
        report = drill.validate_report(json.loads(capsys.readouterr().out), payload)
        assert report['selected_table_counts_checked'] == 5


@pytest.mark.parametrize('captured', [False], indirect=True)
@pytest.mark.parametrize('unexpected', ['file', 'symlink', 'dangling-symlink', 'directory'])
def test_absent_config_requires_both_manifest_and_readback_absence(captured, unexpected):
    restored, _, _, _ = captured
    path = restored / 'data/config.json'
    if unexpected == 'file':
        path.write_text('{}')
    elif unexpected == 'directory':
        path.mkdir()
    else:
        path.symlink_to('db.sqlite3' if unexpected == 'symlink' else 'missing')
    with pytest.raises(Exception) as error:
        drill.build_payload(*captured)
    assert getattr(error.value, 'code', str(error.value)) in {
        'SNAPSHOT_INCOMPLETE', 'PRIVATE_PATH_SYMLINK_REJECTED'}


@pytest.mark.parametrize('captured', [False], indirect=True)
def test_absent_config_payload_allows_only_the_approved_domain_and_keeps_source_absent(captured):
    restored, state, scope, profile = captured
    payload, proof = drill.build_payload(*captured)
    assert proof['configuration_origin'] == 'generated_from_verified_absence'
    assert not (restored / 'data/config.json').exists()
    assert 'config.json' not in {entry['path'] for entry in payload['files']}
    profile['recovery_profile']['environment']['ADMIN_TOKEN'] = 'unapproved'
    with pytest.raises(Exception) as error:
        drill.build_payload(restored, state, scope, profile)
    assert error.value.code == 'TARGET_OVERLAY_UNSUPPORTED'


@pytest.mark.parametrize('change', ['source-before', 'source-after', 'generation', 'checkpoint'])
def test_no_evidence_when_source_or_generation_changes_during_probe(change, monkeypatch):
    probe = object.__new__(drill.ApplicationReadback)
    probe.state = checkpoint()
    probe.profile = {}
    probe.root = Path('/synthetic-only')
    probe.checkpoint = probe.root / 'checkpoint.json'
    probe.checkpoint_bytes = b'synthetic-checkpoint'
    probe.engine = SimpleNamespace(dispose=lambda: None)
    probe.evidence = Path('/synthetic-evidence-never-created')
    scope = catalog()
    second = copy.deepcopy(scope)
    if change == 'generation':
        second['target']['active_generation'] = RUN
    scopes = iter([(scope, {}), (second, {})])
    probe.catalog = lambda: next(scopes)
    probe.api_proof = lambda _job: None

    async def ssh(*_args):
        return {'result': 'synthetic-only'}

    probe.ssh_readback = ssh
    original = probe.state['source_before_restore']
    changed = {**original, 'whole_inventory_sha256': 'e' * 64}
    witnesses = iter([changed if change == 'source-before' else original,
                      changed if change == 'source-after' else original])
    monkeypatch.setattr(drill, 'source_witness', lambda: next(witnesses))
    monkeypatch.setattr(drill, 'build_payload', lambda *_args: ({}, {}))
    monkeypatch.setattr(drill, 'private_read', lambda _path: b'changed' if change == 'checkpoint'
                        else probe.checkpoint_bytes)
    monkeypatch.setattr(drill, 'write_evidence', forbidden)
    with pytest.raises(drill.DrillError, match='SOURCE_CHANGED|CATALOG_CHANGED|CHECKPOINT_CHANGED'):
        probe.execute()


def test_unexpected_private_exceptions_print_only_a_fixed_code(monkeypatch, capsys):
    def fail(_args):
        raise RuntimeError('synthetic-private-token SQL password or SSH stderr must stay private')
    monkeypatch.setattr(drill, 'ApplicationReadback', fail)
    assert drill.main(['--execute', '--root-go', drill.RELEASE, '--dedicated-test-account',
                       '--destination-id', DEST]) == 1
    assert capsys.readouterr().out.strip() == 'APPLICATION_READBACK_FAILED_PRIVATE_DETAILS_WITHHELD'

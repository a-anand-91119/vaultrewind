"""Pure auth-drill contracts: no live SQL, private runtime, Docker, SSH or provider calls."""
from __future__ import annotations

import copy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import prove_drive_auth_failure as drill
from scripts import prove_drive_recovery as recovery

DEST = '81be8f91-7e7c-4531-9ceb-740d4239aa15'
RUN = 'fe65591b-4451-4df0-94c1-29a3cec7cb11'
POINT = '7910f723-d099-4d25-a8df-a990c6279cf1'
LOCAL = 'f7537008-2545-487d-b7dc-a6dac8ee116b'
DRIVE = '4ebbb2a9-bb20-4cbf-9a41-a280041450b6'
REPO = '84fb72e9-a684-4db3-96ab-4b73c51bf2a5'
HASH = 'a' * 64


def forbidden(*_args, **_kwargs):
    pytest.fail('Pure test attempted private/runtime/provider I/O.')


def arguments(*extra):
    return drill.parse_args(['--destination-id', DEST, '--run-id', RUN, '--phase', 'fault',
                             '--dedicated-test-account', *extra])


def policy():
    return {'revision': 12, 'enabled': False, 'schedule_kind': 'hourly', 'timezone': 'Asia/Kolkata',
            'daily_time': '02:17', 'interval_hours': 3, 'retention_days': None, 'outage_seconds': 30,
            'maintenance_seconds': 180, 'validation_seconds': 120, 'runner_id': RUN,
            'next_run_at': None, 'next_verify_at': '2026-11-01T10:00:00+00:00', 'next_test_at': None,
            'destinations': [{'destination_id': LOCAL, 'backend': 'local', 'required': True,
                              'repository_id': REPO},
                             {'destination_id': DRIVE, 'backend': 'drive', 'required': False,
                              'repository_id': POINT}]}


def prior_recovery():
    state = {'version': 1, 'source_id': drill.SOURCE_ID, 'destination_id': DEST, 'run_id': RUN,
             'steps': {}, 'failures': [], 'snapshot_id': POINT, 'local_copy_id': LOCAL,
             'drive_copy_id': DRIVE, 'configuration_sha256': HASH, 'policy_restored': True,
             'alternate_restore': {'complete': True},
             'refresh': {'real_rclone_access_token_refresh_persisted_in_encrypted_sql': True},
             'revocation': {'locally_invalidated': True, 'google_revoke_acknowledged': True,
                            'actual_google_refresh_error': 'STORAGE_AUTH_EXPIRED',
                            'source_unchanged_and_local_copy_verified': True, 'old_grant_sha256': HASH}}
    for backend, copy_id in (('local', LOCAL), ('drive', DRIVE)):
        state[backend + '_readback'] = {'complete': True, 'restored_bytes_verified': True,
            'saved_image_inventory_verified': True, 'sqlite_integrity': 'ok', 'backend': backend,
            'snapshot_id': POINT, 'copy_id': copy_id, 'manifest_hash': HASH, 'whole_file_map_sha256': HASH}
    return state


def state():
    binding = drill.validate_recovery(prior_recovery(), DEST, RUN)
    return {'version': 1, 'source_id': drill.SOURCE_ID, 'destination_id': DEST, 'run_id': RUN,
            'base': binding, 'steps': {}, 'failures': [], 'readbacks': {}, 'retry_attempts': [],
            'snapshot_id': POINT, 'local_copy_id': LOCAL, 'drive_copy_id': DRIVE,
            'drive_repository_id': REPO}


def bare():
    value = object.__new__(drill.AuthFaultDrill)
    value.args, value.run_id, value.destination = arguments(), RUN, DEST
    value.state = state()
    value.state['steps']['fault'] = {'job_id': RUN}
    value.save = lambda: None
    value.idle_source = lambda *a, **k: None
    value.credential_quiet = lambda: None
    value.credential = lambda **kw: {'grant_sha256': HASH, 'generation': DEST}
    value.state['retry_grant'] = value.credential()
    return value


def fault_job():
    return {'id': RUN, 'kind': 'backup', 'instance_id': drill.SOURCE_ID, 'state': 'partial',
            'phase': 'finalizing', 'error_code': 'REQUIRED_COPY_FAILED', 'attempts': 1,
            'content_commit': 'complete', 'required_copy_outcome': 'failed', 'source_service_outcome': 'running',
            'reconcile_required': False, 'result': {'snapshot_id': POINT}}


def snapshot():
    return {'id': POINT, 'instance_id': drill.SOURCE_ID, 'completeness': 'complete', 'copies': [
        {'id': LOCAL, 'backend': 'local', 'state': 'complete', 'repository_id': RUN, 'destination_id': LOCAL},
        {'id': DRIVE, 'backend': 'drive', 'state': 'failed', 'destination_id': DEST,
         'repository_id': REPO, 'error_code': 'STORAGE_AUTH_EXPIRED'}]}


def witness():
    return {'running': True, 'container_id': RUN, 'started_at': '2026-10-26T00:00:00Z',
            'active_generation': None, 'restore_fencing_token': None,
            'whole_inventory_sha256': HASH, 'logical_database_sha256': HASH, 'non_database_sha256': HASH,
            'metadata_sha256': HASH, 'source_journal_count': 4, 'source_journals_sha256': HASH}


def test_preparation_has_no_private_io_or_runtime_construction(monkeypatch, capsys):
    monkeypatch.setattr(drill, 'AuthFaultDrill', forbidden)
    monkeypatch.setattr(drill, 'execution_lock', forbidden)
    monkeypatch.setattr(drill, 'private_read', forbidden)
    monkeypatch.setattr(Path, 'mkdir', forbidden)
    monkeypatch.setattr(Path, 'write_text', forbidden)
    monkeypatch.setattr(recovery, 'DriveDrill', forbidden)
    assert drill.main([]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report['code'] == 'PREPARED_AUTH_FAULT_NOT_EXECUTED'
    assert report['private_files_opened'] == report['network_sql_provider_ssh_docker_calls'] == 0
    assert report['evidence_written'] is False


@pytest.mark.parametrize('extra', [[], ['--execute'], ['--execute', '--root-go', 'ROOTGO'],
                                  ['--root-go', drill.RELEASE]])
def test_constructor_gate_precedes_all_private_reads(extra, monkeypatch):
    monkeypatch.setattr(drill, 'private_read', forbidden)
    with pytest.raises(drill.DrillError, match='PARKED'):
        drill.AuthFaultDrill(arguments(*extra))


@pytest.mark.parametrize('field', ['dedicated_test_account', 'run_id', 'destination_id', 'phase'])
def test_execution_requires_each_explicit_scope_field(field):
    args = arguments('--execute', '--root-go', drill.RELEASE)
    setattr(args, field, None)
    with pytest.raises(drill.DrillError, match='PARKED'):
        drill.require_execution(args)


@pytest.mark.parametrize('flag,value', [('--run-id', '../controller'), ('--destination-id', DEST.upper()),
                                      ('--phase', 'roundtrip'), ('--origin', 'http://example.com')])
def test_no_arbitrary_input_paths_origins_or_phases(flag, value):
    with pytest.raises(SystemExit):
        drill.parse_args([flag, value])


@pytest.mark.parametrize('key', ['locally_invalidated', 'google_revoke_acknowledged',
                               'actual_google_refresh_error', 'source_unchanged_and_local_copy_verified'])
def test_recovery_requires_real_revocation_not_synthetic_expiry(key):
    prior = prior_recovery()
    prior['revocation'].pop(key)
    with pytest.raises(drill.DrillError, match='REAL_GOOGLE_REVOCATION'):
        drill.validate_recovery(prior, DEST, RUN)


@pytest.mark.parametrize('mutation', ['alternate', 'local', 'drive', 'map', 'run'])
def test_recovery_rejects_unbound_or_incomplete_proofs(mutation):
    prior = prior_recovery()
    if mutation == 'alternate':
        prior['alternate_restore']['complete'] = False
    elif mutation in {'local', 'drive'}:
        prior[mutation + '_readback']['copy_id'] = RUN
    elif mutation == 'map':
        prior['local_readback']['whole_file_map_sha256'] = 'b' * 64
    else:
        prior['run_id'] = DEST
    with pytest.raises(drill.DrillError):
        drill.validate_recovery(prior, DEST, RUN)


def test_completed_retention_must_match_this_recovery_baseline():
    binding = state()['base']
    report = {'run_id': RUN, 'destination_id': DEST, 'result': 'live_retention_proven',
              'retention_live_proven': True, 'input_snapshot_id': POINT, 'input_manifest_hash': HASH,
              'configuration_sha256': HASH, 'rounds': [{'complete': True}, {'complete': True}]}
    drill.validate_retention(report, binding, DEST, RUN)
    report['input_snapshot_id'] = LOCAL
    with pytest.raises(drill.DrillError, match='LIVE_RETENTION'):
        drill.validate_retention(report, binding, DEST, RUN)


def test_run_uuid_change_cannot_bypass_ambiguous_submission_or_reuse_revoked_grant():
    prior = state()
    prior['run_id'] = LOCAL
    prior['steps']['fault'] = {'attempted': True}
    with pytest.raises(drill.DrillError, match='OTHER_RUN_SUBMISSION'):
        drill.guard_other_runs([prior], state()['base'], DEST, RUN)
    prior['steps'] = {}
    with pytest.raises(drill.DrillError, match='REVOKED_GRANT_ALREADY_BOUND'):
        drill.guard_other_runs([prior], state()['base'], DEST, RUN)


def test_checkpoint_rebind_and_idempotency_key_change_are_rejected():
    value = state()
    value['base']['snapshot_id'] = RUN
    with pytest.raises(drill.DrillError, match='BINDING'):
        drill.validate_state(value, state()['base'], DEST, RUN)
    value = state()
    value['steps']['retry'] = {'idempotency_key': 'fresh-key'}
    with pytest.raises(drill.DrillError, match='STABLE_IDENTITY'):
        drill.validate_state(value, state()['base'], DEST, RUN)


def test_fault_policy_preserves_all_fields_and_other_destination_flags():
    original = policy()
    saved = copy.deepcopy(original)
    changed = drill.fault_policy(original, DEST)
    assert original == saved
    assert changed['destinations'][:-1] == drill.policy_body(original)['destinations']
    assert changed['destinations'][-1] == {'destination_id': DEST, 'required': True}
    assert {k: changed[k] for k in recovery.POLICY_FIELDS} == {k: original[k] for k in recovery.POLICY_FIELDS}
    changed = drill.fault_policy(original, DRIVE)
    assert changed['destinations'][1]['required'] is True
    assert original['destinations'][1]['required'] is False


@pytest.mark.parametrize('change', ['enabled', 'no_required_local'])
def test_fault_requires_disabled_policy_with_required_local(change):
    original = policy()
    if change == 'enabled':
        original['enabled'] = True
    else:
        original['destinations'][0]['required'] = False
    with pytest.raises(drill.DrillError, match='DISABLED_POLICY'):
        drill.fault_policy(original, DEST)


def test_policy_install_response_loss_still_restores_exact_original():
    value = bare()
    original = policy()
    current = copy.deepcopy(original)
    value.recovery = {'original_policy': original, 'local_readback': {'repository_id': REPO}}
    value.policy = lambda: copy.deepcopy(current)
    durable = []
    value.save = lambda: durable.append(copy.deepcopy(value.state))

    def patch(view, body, stage):
        nonlocal current
        assert view['revision'] == current['revision']
        current.update(copy.deepcopy(body), revision=current['revision'] + 1)
        if stage == 'install':
            assert durable[-1]['policy_mutation_intent']
            raise TimeoutError('PRIVATE_RESPONSE')
        return copy.deepcopy(current)

    value.patch_policy = patch
    with pytest.raises(TimeoutError):
        value.install_policy()
    value.restore_policy()
    assert drill.canonical_policy(current) == drill.canonical_policy(original)
    assert all(current[k] == original[k] for k in drill.SCHEDULES)
    assert current['enabled'] is False and value.state['policy_restored']


def test_policy_restore_reconciles_lost_restore_response_without_second_patch():
    value = bare()
    original = policy()
    value.state.update(original_policy=original, policy_mutation_intent=True, policy_restored=False)
    value.policy = lambda: original
    value.patch_policy = forbidden
    value.restore_policy()
    assert value.state['policy_restored']


def test_policy_restore_refuses_concurrent_edits():
    value = bare()
    original = policy()
    value.state.update(original_policy=original, policy_mutation_intent=True)
    current = dict(drill.fault_policy(original, DEST), revision=13, next_run_at=None,
                   next_verify_at=original['next_verify_at'], next_test_at=None)
    current['retention_days'] = 14
    value.policy = lambda: current
    value.patch_policy = forbidden
    with pytest.raises(drill.DrillError, match='CONCURRENT_CHANGE'):
        value.restore_policy()


def test_lost_submission_response_never_repeats_post_and_retains_exact_plan():
    value = bare()
    saves, posts = [], []
    value.save = lambda: saves.append(copy.deepcopy(value.state))

    def request(method, path, body, **kwargs):
        assert saves[-1]['steps']['retry']['attempted'] is True
        posts.append((method, path, body, kwargs['key']))
        raise TimeoutError('PRIVATE_TOKEN')

    value.request = request
    with pytest.raises(TimeoutError):
        value.submit('retry')
    value.lookup_job = lambda record: (_ for _ in ()).throw(drill.DrillError('UNRESOLVED'))
    with pytest.raises(drill.DrillError, match='UNRESOLVED'):
        value.submit('retry')
    assert posts == [('POST', '/snapshot-copies/' + DRIVE + '/retry', {}, 'drive-auth:' + RUN + ':retry')]
    assert value.state['steps']['retry']['planned_job']['request'] == {
        'snapshot_id': POINT, 'repository_id': REPO, 'original_job_id': RUN}


def test_existing_job_id_only_reconciles_and_does_not_resubmit():
    value = bare()
    value.state['steps']['fault'] = {'job_id': RUN}
    plan = value.planned_job('retry')
    value.state['steps']['retry'] = {'idempotency_key': f'drive-auth:{RUN}:retry', 'planned_job': plan,
                                   'attempted': True, 'job_id': DEST}
    value.request = forbidden
    value.lookup_job = lambda record: {'id': DEST}
    assert value.submit('retry') == DEST


@pytest.mark.parametrize('field,value', [('snapshot_id', LOCAL), ('repository_id', LOCAL),
                                       ('original_job_id', LOCAL)])
def test_reconciled_retry_job_must_match_exact_saved_plan(field, value):
    planned = {'kind': 'retry_copy', 'request': {'snapshot_id': POINT, 'repository_id': REPO,
                                              'original_job_id': RUN}}
    job = {'kind': 'retry_copy', 'instance_id': drill.SOURCE_ID, 'request': copy.deepcopy(planned['request'])}
    drill.validate_planned_job(job, planned)
    job['request'][field] = value
    with pytest.raises(drill.DrillError, match='DURABLE_PLAN'):
        drill.validate_planned_job(job, planned)


@pytest.mark.parametrize('change', ['succeeded', 'source_stopped', 'cloud_uncertain', 'wrong_auth_code', 'wrong_local'])
def test_fault_does_not_force_a_different_actual_result_to_pass(change):
    job, point = fault_job(), snapshot()
    if change == 'succeeded':
        job['state'] = 'succeeded'
    elif change == 'source_stopped':
        job['source_service_outcome'] = 'stopped'
    elif change == 'cloud_uncertain':
        point['copies'][1]['state'] = 'uncertain'
    elif change == 'wrong_auth_code':
        point['copies'][1]['error_code'] = 'STORAGE_NETWORK_ERROR'
    else:
        point['copies'][0]['id'] = RUN
    with pytest.raises(drill.DrillError):
        drill.validate_fault(job, point, DEST, LOCAL)


def test_real_partial_with_actual_auth_expired_copy_passes():
    assert drill.validate_fault(fault_job(), snapshot(), DEST, LOCAL)['id'] == DRIVE


@pytest.mark.parametrize('field', ['started_at', 'active_generation', 'restore_fencing_token',
                                 'whole_inventory_sha256', 'source_journal_count',
                                 'source_journals_sha256', 'logical_database_sha256', 'non_database_sha256',
                                 'metadata_sha256', 'container_id', 'running'])
def test_retry_rejects_source_recapture_or_content_change(field):
    before, after = witness(), witness()
    after[field] = False if field == 'running' else 'changed'
    with pytest.raises(drill.DrillError, match='SOURCE_CHANGED_DURING_RETRY'):
        drill.compare_source(before, after, retry=True)


def test_fault_allows_expected_source_restart_but_no_logical_or_file_change():
    before, after = witness(), witness()
    after.update(started_at='later', whole_inventory_sha256='b' * 64, source_journal_count=5,
                 source_journals_sha256='b' * 64)
    drill.compare_source(before, after, retry=False)
    after['non_database_sha256'] = 'b' * 64
    with pytest.raises(drill.DrillError, match='SOURCE_CONTENT_CHANGED'):
        drill.compare_source(before, after, retry=False)


def test_retry_method_targets_failed_copy_preserves_partial_and_never_installs_policy():
    value = bare()
    value.args.phase = 'retry'
    original = fault_job()
    value.state.update(fault_proven=True, policy_restored=True)
    value.state['steps']['fault'] = {'job_id': RUN,
        'terminal_observation': {k: original[k] for k in drill.JOB_FIELDS}}
    value.state['readbacks']['fault_local'] = {'complete': True}
    value.lookup_job = lambda record: original if record is value.state['steps']['fault'] else {'id': DEST}
    value.credential = lambda **kw: {'grant_sha256': HASH, 'generation': DEST}
    value.source_witness = witness
    value.install_policy = forbidden
    calls = []
    complete = snapshot()
    complete['copies'][1]['state'] = 'complete'

    def request(method, path, body=None, **kw):
        calls.append((method, path, body))
        if method == 'POST':
            assert path == '/snapshot-copies/' + DRIVE + '/retry'
            assert body == {}
            return {'job_id': DEST}
        return complete if value.state['steps'].get('retry', {}).get('job_id') else snapshot()

    value.request = request
    job = {**original, 'id': DEST, 'kind': 'retry_copy', 'state': 'succeeded', 'error_code': None,
           'required_copy_outcome': 'complete'}
    value.wait = lambda stage: job
    value.readback = lambda *a: {'manifest_hash': HASH, 'whole_file_map_sha256': HASH}
    value.base_readback = lambda stage: None
    value.retry()
    assert value.state['retry_proven']
    assert value.state['source_before_retry'] == value.state['source_after_retry']
    assert [c for c in calls if c[0] == 'POST'] == [('POST', '/snapshot-copies/' + DRIVE + '/retry', {})]
    assert original['state'] == 'partial' and original['error_code'] == 'REQUIRED_COPY_FAILED'


def test_execute_preserves_primary_and_policy_restore_errors_and_publishes_partial():
    value = bare()
    value.catalog_binding = lambda: None
    value.fault = lambda: (_ for _ in ()).throw(drill.DrillError('ACTUAL_RESULT_DIFFERS'))
    value.restore_policy = lambda: (_ for _ in ()).throw(drill.DrillError('ACTIVE_JOB_PRESERVED'))
    value.final_verification = lambda: None
    published = []
    value.publish = lambda: published.append(copy.deepcopy(value.state))
    with pytest.raises(drill.DrillError, match='ACTUAL_RESULT_DIFFERS'):
        value.execute()
    assert published[0]['policy_restored'] is False
    assert [e['code'] for e in published[0]['failures']] == ['ACTUAL_RESULT_DIFFERS', 'ACTIVE_JOB_PRESERVED']


def test_raw_errors_and_arbitrary_progress_are_never_printed(monkeypatch, capsys):
    class Unsafe(Exception):
        code = 'PRIVATE=token'

    monkeypatch.setattr(drill, 'execution_lock', lambda args: (_ for _ in ()).throw(Unsafe('secret-token')))
    assert drill.main(['--execute', '--root-go', drill.RELEASE, '--dedicated-test-account',
                       '--destination-id', DEST, '--run-id', RUN, '--phase', 'fault']) == 1
    assert json.loads(capsys.readouterr().out) == {'code': 'AUTH_DRILL_FAILURE'}
    drill.progress('SAFE_ENUM', 'secret-token')
    assert json.loads(capsys.readouterr().out) == {'code': 'SAFE_ENUM'}


def test_no_revoked_drive_readback_even_if_a_caller_requests_it():
    value = bare()
    value.sessions = forbidden
    with pytest.raises(drill.DrillError, match='REVOKED_DRIVE_READ_FORBIDDEN'):
        value.readback('forbidden', POINT, DRIVE, 'drive')


@pytest.mark.parametrize('revoked,grant', [(False, 'old-google-grant'), (False, 'local-invalidated-grant'),
                                        (True, 'fresh-google-grant')])
def test_retry_requires_a_fresh_nonrevoked_grant_without_mutating_credentials(revoked, grant):
    value = bare()
    value.args.phase = 'retry'
    credential = {'type': 'google_drive_oauth', 'scope': 'drive.file', 'grant_id': grant,
                  'revoked': revoked, 'token': {'refresh_token': 'synthetic-refresh'}}
    original = copy.deepcopy(credential)
    value.state['base']['old_grant_sha256'] = drill.digest('old-google-grant')
    value.state['revoked_credential'] = {'grant_sha256': drill.digest('local-invalidated-grant')}
    value.store = SimpleNamespace(load=lambda dest: SimpleNamespace(envelope='encrypted', generation=RUN))
    value.box = SimpleNamespace(decrypt=lambda envelope, **kw: credential)
    value.secret_values = []
    value.request = forbidden
    # Use the implementation method rather than bare()'s pure submission stub.
    with pytest.raises(drill.DrillError, match='FRESH_PRIVATE_UI_RECONNECT'):
        drill.AuthFaultDrill.credential(value, revoked=False)
    assert credential == original


def test_fault_rejects_nonrevoked_sql_credential_before_any_provider_action():
    value = bare()
    credential = {'type': 'google_drive_oauth', 'scope': 'drive.file', 'grant_id': 'fresh-google-grant'}
    value.store = SimpleNamespace(load=lambda dest: SimpleNamespace(envelope='encrypted', generation=RUN))
    value.box = SimpleNamespace(decrypt=lambda envelope, **kw: credential)
    value.secret_values = []
    value.request = forbidden
    with pytest.raises(drill.DrillError, match='LOCALLY_REVOKED_SQL_GRANT_REQUIRED'):
        drill.AuthFaultDrill.credential(value, revoked=True)


def test_actual_revoked_sql_grant_must_match_old_credential_and_stay_unchanged():
    value = bare()
    old = {'type': 'google_drive_oauth', 'scope': 'drive.file', 'grant_id': 'old-google-grant',
           'folder_id': 'synthetic-folder', 'client_id': 'synthetic-client', 'client_secret': 'synthetic-secret',
           'token': {'access_token': 'synthetic-access', 'refresh_token': 'synthetic-refresh'}}
    credential = {**copy.deepcopy(old), 'grant_id': 'local-invalidated-grant',
                  'revoked': True, 'revoked_at': '2026-10-26T00:00:00Z'}
    original = copy.deepcopy(credential)
    value.state['base']['old_grant_sha256'] = drill.digest(old['grant_id'])
    config = {'folder_id': 'synthetic-folder', 'scope': 'drive.file'}
    value.state['base']['configuration_sha256'] = drill.digest(config)
    value.recovery = {'revocation': {'encrypted_old_credential': 'encrypted-old'}}
    value.store = SimpleNamespace(load=lambda dest: SimpleNamespace(envelope='encrypted-current', generation=RUN))
    value.box = SimpleNamespace(decrypt=lambda envelope, **kw: old if envelope == 'encrypted-old' else credential)
    value.secret_values = []
    value.request = lambda *a: {'backend': 'drive', 'configuration': config}
    result = drill.AuthFaultDrill.credential(value, revoked=True)
    assert result == {'grant_sha256': drill.digest('local-invalidated-grant'), 'generation': RUN}
    assert credential == original
    credential['token']['refresh_token'] = 'unrelated-refresh'
    with pytest.raises(drill.DrillError, match='SQL_REVOKED_CREDENTIAL_NOT_BOUND_TO_RECOVERY'):
        drill.AuthFaultDrill.credential(value, revoked=True)


def test_pending_or_registered_credential_state_blocks_submission_without_erasing_work():
    value = bare()
    value.credential_quiet = lambda: (_ for _ in ()).throw(
        drill.DrillError('REGISTERED_DRIVE_SESSIONS_REQUIRE_PRODUCT_RECOVERY'))
    value.request = forbidden
    with pytest.raises(drill.DrillError, match='REGISTERED_DRIVE_SESSIONS'):
        value.submit('retry')
    assert not value.state['steps']['retry'].get('attempted')
    assert 'planned_job' in value.state['steps']['retry']


def test_final_verification_rechecks_base_and_source_after_an_unexpected_fault():
    value = bare()
    value.state['source_before_fault'] = witness()
    reads = []
    value.base_readback = lambda stage: reads.append(stage)
    value.readback = lambda stage, *a: reads.append(stage)
    value.source_witness = witness
    value.final_verification()
    assert reads == ['base_final_fault', 'fault_local']
    assert value.state['source_final_fault'] == witness()


def restored_source():
    """Docker inspect shape for an original-target restore, with a historical enrollment ID."""
    configuration = {'revision': 8, 'fingerprint': HASH, 'physical_identity': HASH,
                     'container_id': 'a' * 64, 'active_generation': RUN}
    descriptor = {'Id': 'b' * 64, 'Name': '/vr-ssh-source', 'Image': 'sha256:' + 'c' * 64,
                  'State': {'Running': True, 'StartedAt': '2026-10-26T00:00:00Z'},
                  'Config': {'Labels': {'org.vaultrewind.instance': drill.SOURCE_ID,
                                        'org.vaultrewind.operation': RUN, 'org.vaultrewind.role': 'active'}},
                  'Mounts': [{'Type': 'bind', 'Source': str(drill.SOURCE), 'Destination': '/data', 'RW': True}]}
    job = {**fault_job(), 'id': RUN, 'kind': 'restore', 'state': 'succeeded', 'error_code': None,
           'content_commit': 'complete', 'target_activation_outcome': 'complete', 'fencing_token': 19,
           'request': {'target_id': drill.SOURCE_ID},
           'result': {'active_generation': RUN, 'candidate_validated': True, 'activation_started': True,
                      'application_started': True, 'restored_bytes_verified': True}}
    journal = {'operation_id': RUN, 'instance_id': drill.SOURCE_ID, 'kind': 'restore', 'phase': 'complete',
               'active_generation': RUN, 'fencing_token': 19, 'final_id': descriptor['Id'],
               'final_name': 'vr-ssh-source', 'activation_started': True, 'watchdog_armed': False,
               'source_service_outcome': 'running'}
    return configuration, descriptor, job, journal


def test_historical_enrollment_container_id_accepts_proven_current_restore_descriptor():
    configuration, descriptor, job, journal = restored_source()
    assert descriptor['Id'] != configuration['container_id']
    original = copy.deepcopy((configuration, descriptor, job, journal))
    assert drill.validate_source_descriptor(descriptor, configuration, job, journal) == {
        'active_generation': RUN, 'restore_fencing_token': 19}
    assert (configuration, descriptor, job, journal) == original


@pytest.mark.parametrize('current_id_matches_enrollment', [False, True])
def test_wrong_generation_is_rejected_even_if_current_container_matches_enrollment(current_id_matches_enrollment):
    configuration, descriptor, job, journal = restored_source()
    if current_id_matches_enrollment:
        descriptor['Id'] = configuration['container_id']
        journal['final_id'] = descriptor['Id']
    descriptor['Config']['Labels']['org.vaultrewind.operation'] = POINT
    with pytest.raises(drill.DrillError, match='SOURCE_ACTIVE_GENERATION_LABEL_MISMATCH'):
        drill.validate_source_descriptor(descriptor, configuration, job, journal)


@pytest.mark.parametrize('field,value', [('Name', '/foreign-source'), ('Id', 'not-a-real-docker-id'),
                                       ('running', False), ('instance', DEST), ('root', '/srv/foreign/data'),
                                       ('mount_type', 'volume'), ('role', 'candidate')])
def test_current_generation_never_bypasses_fixed_source_identity(field, value):
    configuration, descriptor, job, journal = restored_source()
    if field in {'Name', 'Id'}:
        descriptor[field] = value
    elif field == 'running':
        descriptor['State']['Running'] = value
    elif field in {'instance', 'role'}:
        descriptor['Config']['Labels']['org.vaultrewind.' + field] = value
    else:
        descriptor['Mounts'][0]['Source' if field == 'root' else 'Type'] = value
    with pytest.raises(drill.DrillError):
        drill.validate_source_descriptor(descriptor, configuration, job, journal)


@pytest.mark.parametrize('field,value', [('state', 'needs_attention'), ('instance_id', DEST),
                                       ('kind', 'backup'), ('reconcile_required', True), ('fencing_token', 0),
                                       ('target_activation_outcome', 'activation_started')])
def test_active_source_requires_real_succeeded_restore_job(field, value):
    configuration, descriptor, job, journal = restored_source()
    job[field] = value
    with pytest.raises(drill.DrillError, match='SOURCE_SUCCEEDED_CURRENT_RESTORE_REQUIRED'):
        drill.validate_source_descriptor(descriptor, configuration, job, journal)


@pytest.mark.parametrize('field,value', [('fencing_token', 18), ('final_id', 'd' * 64),
                                       ('active_generation', POINT), ('instance_id', DEST),
                                       ('phase', 'activating'), ('watchdog_armed', True)])
def test_active_source_requires_matching_current_helper_fence_and_container(field, value):
    configuration, descriptor, job, journal = restored_source()
    journal[field] = value
    with pytest.raises(drill.DrillError, match='SOURCE_CURRENT_RESTORE_FENCE_UNPROVEN'):
        drill.validate_source_descriptor(descriptor, configuration, job, journal)


def test_initial_untouched_source_requires_enrollment_id_and_no_operation_label():
    configuration, descriptor, _job, _journal = restored_source()
    configuration['active_generation'] = None
    descriptor['Id'] = configuration['container_id']
    descriptor['Config']['Labels'] = {'org.vaultrewind.instance': drill.SOURCE_ID}
    assert drill.validate_source_descriptor(descriptor, configuration) == {
        'active_generation': None, 'restore_fencing_token': None}
    descriptor['Config']['Labels']['org.vaultrewind.operation'] = RUN
    with pytest.raises(drill.DrillError, match='INITIAL_SOURCE_IDENTITY_CHANGED'):
        drill.validate_source_descriptor(descriptor, configuration)
    descriptor['Config']['Labels'].pop('org.vaultrewind.operation')
    descriptor['Id'] = 'd' * 64
    with pytest.raises(drill.DrillError, match='INITIAL_SOURCE_IDENTITY_CHANGED'):
        drill.validate_source_descriptor(descriptor, configuration)


def unissued_legacy_checkpoint():
    value = state()
    for key in ('snapshot_id', 'local_copy_id', 'drive_copy_id', 'drive_repository_id'):
        value.pop(key)
    configuration, _descriptor, _job, _journal = restored_source()
    value['source_configuration'] = {k: v for k, v in configuration.items() if k != 'active_generation'}
    value['readbacks']['base_before_fault'] = copy.deepcopy(prior_recovery()['local_readback'])
    value['failures'] = [{'phase': 'fault', 'code': 'EXACT_RUNNING_SYNTHETIC_SOURCE_REQUIRED'}]
    return value, configuration


def test_legacy_preflight_migration_adds_only_generation_and_preserves_initial_failure_and_readback():
    value, configuration = unissued_legacy_checkpoint()
    previous = copy.deepcopy(value)
    result = drill.bind_source_configuration(value, configuration)
    assert value == previous  # Caller saves only after the remaining catalog guards pass.
    value['source_configuration'] = result
    expected = copy.deepcopy(previous)
    expected['source_configuration']['active_generation'] = RUN
    assert value == expected
    assert drill.bind_source_configuration(value, configuration) == configuration


@pytest.mark.parametrize('key,value', [('policy_mutation_intent', False), ('source_before_fault', {}),
                                     ('snapshot_id', POINT), ('original_policy', {}), ('fault_proven', False)])
def test_legacy_migration_rejects_any_issued_or_later_checkpoint_marker(key, value):
    checkpoint, configuration = unissued_legacy_checkpoint()
    checkpoint[key] = value
    with pytest.raises(drill.DrillError, match='MIGRATION_REQUIRES_UNISSUED_PREFLIGHT'):
        drill.bind_source_configuration(checkpoint, configuration)


@pytest.mark.parametrize('record', [{'attempted': True}, {'job_id': RUN}, {'idempotency_key': 'planned'}])
def test_legacy_migration_cannot_rebind_any_job_intent_or_existing_id(record):
    checkpoint, configuration = unissued_legacy_checkpoint()
    checkpoint['steps']['fault'] = record
    saved = copy.deepcopy(checkpoint)
    with pytest.raises(drill.DrillError, match='MIGRATION_REQUIRES_UNISSUED_PREFLIGHT'):
        drill.bind_source_configuration(checkpoint, configuration)
    assert checkpoint == saved


@pytest.mark.parametrize('field', ['revision', 'fingerprint', 'physical_identity', 'container_id'])
def test_legacy_migration_rejects_any_change_to_existing_binding_fields(field):
    checkpoint, configuration = unissued_legacy_checkpoint()
    configuration[field] = 'changed'
    with pytest.raises(drill.DrillError, match='SOURCE_CONFIGURATION_CHANGED'):
        drill.bind_source_configuration(checkpoint, configuration)


@pytest.mark.parametrize('mutation', ['incomplete_local', 'different_copy', 'different_error', 'different_generation'])
def test_legacy_migration_requires_exact_failure_bound_proof_and_generation(mutation):
    checkpoint, configuration = unissued_legacy_checkpoint()
    if mutation == 'incomplete_local':
        checkpoint['readbacks']['base_before_fault']['complete'] = False
    elif mutation == 'different_copy':
        checkpoint['readbacks']['base_before_fault']['copy_id'] = RUN
    elif mutation == 'different_error':
        checkpoint['failures'][0]['code'] = 'UNKNOWN_SUBMISSION_OUTCOME'
    else:
        checkpoint['source_configuration']['active_generation'] = POINT
    with pytest.raises(drill.DrillError):
        drill.bind_source_configuration(checkpoint, configuration)


@pytest.mark.parametrize('phase', ['fault', 'retry'])
def test_actual_current_docker_id_must_remain_unchanged_across_both_phases(phase):
    before, after = witness(), witness()
    after['container_id'] = 'd' * 64
    with pytest.raises(drill.DrillError):
        drill.compare_source(before, after, retry=phase == 'retry')


def test_interrupted_readback_preserves_adapter_work_without_cleanup(tmp_path, monkeypatch):
    """Exercise the real early readback boundary with in-memory catalog doubles."""
    value = bare()
    value.root = tmp_path
    value.state['readbacks']['fault_local'] = {'attempted': True}
    point = SimpleNamespace(instance_id=drill.SOURCE_ID, completeness='complete', manifest_hash=HASH)
    item = SimpleNamespace(repository_id=REPO, snapshot_id=POINT, state='complete', manifest_hash=HASH,
                           restic_snapshot_id=HASH)
    repo = SimpleNamespace(instance_id=drill.SOURCE_ID, destination_id=DEST, id=REPO)
    dest = SimpleNamespace(backend='local', archived=False)
    point.id = POINT
    from vaultrewind.server.models import Repository, Snapshot, SnapshotCopy, StorageDestination

    class Session:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def get(self, model, ident):
            return {Snapshot: point, SnapshotCopy: item, Repository: repo, StorageDestination: dest}[model]

    value.sessions = Session
    value.adapters = SimpleNamespace(repository=forbidden)
    monkeypatch.setattr(Path, 'mkdir', forbidden)
    monkeypatch.setattr(Path, 'unlink', forbidden)
    with pytest.raises(drill.DrillError, match='READBACK_INTERRUPTED_PRESERVE_PRIVATE_WORK'):
        value.readback('fault_local', POINT, LOCAL, 'local')

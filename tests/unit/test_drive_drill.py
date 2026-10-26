"""Pure preparation/gate tests. No SQL, sockets, subprocesses, providers or fixture writes."""
from __future__ import annotations

import copy
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from scripts import prove_drive_recovery as drill

DEST = '81be8f91-7e7c-4531-9ceb-740d4239aa15'
RUN = 'fe65591b-4451-4df0-94c1-29a3cec7cb11'


def arguments(*extra):
    return drill.parse_args(['--dedicated-test-account', '--destination-id', DEST, '--phase', 'roundtrip', *extra])


def checkpoint():
    return {'version': 1, 'source_id': drill.SOURCE_ID, 'destination_id': DEST, 'run_id': RUN,
            'steps': {}, 'failures': []}


def forbidden(*_args, **_kwargs):
    pytest.fail('Preparation attempted external work or a file mutation.')


def test_preparation_never_constructs_runtime_or_writes_files(monkeypatch, capsys):
    monkeypatch.setattr(drill, 'DriveDrill', forbidden)
    monkeypatch.setattr(Path, 'mkdir', forbidden)
    monkeypatch.setattr(Path, 'write_text', forbidden)
    assert drill.main(['--dedicated-test-account', '--destination-id', DEST, '--phase', 'roundtrip']) == 0
    report = json.loads(capsys.readouterr().out)
    assert report['status'] == 'prepared_external_actions_parked'
    assert report['network_sql_provider_ssh_docker_calls'] == 0
    assert report['evidence_written'] is False


@pytest.mark.parametrize('extra', [[], ['--execute'], ['--execute', '--root-go', 'WRONG']])
def test_runtime_constructor_rejects_before_any_private_file_read(extra, monkeypatch):
    monkeypatch.setattr(drill, 'private_read', forbidden)
    with pytest.raises(drill.DrillError, match='DRIVE_IS_PARKED'):
        drill.DriveDrill(arguments(*extra))


def test_execution_flag_is_required_even_when_root_go_is_present():
    with pytest.raises(drill.DrillError, match='DRIVE_IS_PARKED'):
        drill.require_execution(arguments('--root-go', 'ROOTGO'))


def test_explicit_dedicated_account_acknowledgement_is_required():
    args = arguments('--execute', '--root-go', 'ROOTGO')
    args.dedicated_test_account = False
    with pytest.raises(drill.DrillError, match='DRIVE_IS_PARKED'):
        drill.require_execution(args)


@pytest.mark.parametrize('value', ['not-an-id', '../controller/master', DEST.upper(), '00000000-0000-0000-0000-000000000000'])
def test_destination_cannot_be_inferred_from_unsafe_or_noncanonical_id(value):
    with pytest.raises(Exception) as error:
        drill.identifier(value)
    assert error.type.__name__ == 'ArgumentTypeError'


def test_target_requires_separate_serialized_go_and_public_origin():
    args = arguments('--execute', '--root-go', 'ROOTGO', '--target-id', drill.ALTERNATE_ID)
    with pytest.raises(drill.DrillError, match='SERIALIZED_ALTERNATE'):
        drill.require_execution(args)
    args.target_go = 'ROOTGO_TARGET'
    args.target_public_origin = 'http://127.0.0.1:18100'
    drill.require_execution(args)


def test_primary_restore_is_always_rejected():
    args = arguments('--execute', '--root-go', 'ROOTGO', '--target-id', drill.SOURCE_ID,
                     '--target-go', 'ROOTGO_TARGET', '--target-public-origin', 'http://127.0.0.1:18180')
    with pytest.raises(drill.DrillError, match='SERIALIZED_ALTERNATE'):
        drill.require_execution(args)


@pytest.mark.parametrize('port', [8098, 18180])
def test_target_probe_cannot_point_back_to_controller_or_primary_source(port):
    args = arguments('--execute', '--root-go', 'ROOTGO', '--target-id', drill.ALTERNATE_ID,
                     '--target-go', 'ROOTGO_TARGET', '--target-public-origin', f'http://127.0.0.1:{port}')
    with pytest.raises(drill.DrillError, match='SERIALIZED_ALTERNATE'):
        drill.require_execution(args)


@pytest.mark.parametrize('origin', ['https://example.com', 'http://169.254.169.254:8080',
                                   'http://user:pass@127.0.0.1:18100', 'http://127.0.0.1:18100/private',
                                   'http://127.0.0.1:18100?token=value'])
def test_target_origin_is_exact_loopback_and_has_no_secret_components(origin):
    with pytest.raises(Exception) as error:
        drill.loopback_origin(origin)
    assert error.type.__name__ == 'ArgumentTypeError'


def test_revocation_requires_its_own_later_scope_in_reconnect_phase():
    args = arguments('--execute', '--root-go', 'ROOTGO', '--revoke-dedicated-grant')
    with pytest.raises(drill.DrillError, match='SEPARATE_REVOCATION'):
        drill.require_execution(args)
    args.phase = 'reconnect'
    args.revocation_go = 'ROOTGO_REVOKE'
    drill.require_execution(args)


def test_no_registered_session_or_pending_rotation_can_be_overwritten():
    drill.guard_credential_state(0, 0, False)
    for pending, sessions, owned in [(1, 0, False), (0, 1, False), (0, 0, True)]:
        with pytest.raises(drill.DrillError):
            drill.guard_credential_state(pending, sessions, owned)


def test_expiry_fault_changes_only_access_expiry_and_preserves_original_object():
    original = {'type': 'google_drive_oauth', 'grant_id': 'synthetic-grant', 'client_secret': 'synthetic-value',
                'token': {'access_token': 'synthetic-access', 'refresh_token': 'synthetic-refresh',
                          'expiry': '2030-01-01T00:00:00Z', 'token_type': 'Bearer'}}
    saved = copy.deepcopy(original)
    changed = drill.expired_access_only(original, datetime(2026, 10, 26, tzinfo=UTC))
    assert original == saved
    assert changed['token']['expiry'] == '2026-10-25T23:00:00Z'
    changed['token']['expiry'] = original['token']['expiry']
    assert changed == original


@pytest.mark.parametrize('changes', [{'revoked': True}, {'revoked_at': '2026-01-01T00:00:00Z'},
                                    {'type': 'google_drive_client'}, {'grant_id': ''}, {'token': {}}])
def test_expiry_fault_requires_a_current_refreshable_authorized_grant(changes):
    credential = {'type': 'google_drive_oauth', 'grant_id': 'synthetic-grant',
                  'token': {'access_token': 'synthetic-access', 'refresh_token': 'synthetic-refresh'}}
    with pytest.raises(drill.DrillError):
        drill.expired_access_only({**credential, **changes}, datetime.now(UTC))


def test_unknown_response_never_becomes_an_automatic_new_submission():
    assert drill.submission_action({}) == 'submit_once'
    assert drill.submission_action({'attempted': True}) == 'lookup_existing'
    assert drill.submission_action({'attempted': True, 'job_id': RUN}) == 'wait_existing'


@pytest.mark.parametrize('field,value', [('destination_id', RUN), ('run_id', DEST), ('source_id', RUN), ('version', 2)])
def test_checkpoint_cannot_rebind_to_another_source_destination_or_run(field, value):
    state = checkpoint()
    state[field] = value
    with pytest.raises(drill.DrillError, match='CHECKPOINT_IDENTITY'):
        drill.validate_checkpoint(state, DEST, RUN)


def test_checkpoint_rejects_primary_restore_and_job_path_injection():
    state = checkpoint()
    state['restore_plan'] = {'target_id': drill.SOURCE_ID}
    with pytest.raises(drill.DrillError, match='CHECKPOINT_PRIMARY'):
        drill.validate_checkpoint(state, DEST, RUN)
    state = checkpoint()
    state['steps'] = {'restore': {'job_id': '../instances'}}
    with pytest.raises(drill.DrillError, match='CHECKPOINT_JOB_ID'):
        drill.validate_checkpoint(state, DEST, RUN)


def test_policy_restoration_keeps_runner_schedule_budgets_and_required_flags():
    original = {field: None for field in drill.POLICY_FIELDS}
    original.update(enabled=False, runner_id=RUN, timezone='Asia/Kolkata', retention_days=30,
                    outage_seconds=300, maintenance_seconds=900, validation_seconds=120,
                    destinations=[{'destination_id': RUN, 'required': True, 'repository_id': DEST}])
    result = drill.policy_body(original)
    assert result['runner_id'] == RUN and result['enabled'] is False and result['timezone'] == 'Asia/Kolkata'
    assert result['destinations'] == [{'destination_id': RUN, 'required': True}]
    assert original['destinations'][0]['repository_id'] == DEST

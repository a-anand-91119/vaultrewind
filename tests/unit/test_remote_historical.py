"""Historical-status migration with real private journals and explicit Docker/systemd doubles.

No shared helper state, containers, sockets or SSH are accessed by these tests.
"""
import copy
import hashlib
import uuid
from pathlib import Path

import pytest

from tests.unit import test_remote_lifecycle as lifecycle
from vaultrewind.core.errors import VaultRewindError
from vaultrewind.remote.journal import Journal, Locks, atomic_json
from vaultrewind.remote.recovery import process_identity

fixture = lifecycle.fixture


def restore(service, captured, fence):
    op = lifecycle.stage(service, captured, fence=fence)
    safety = service.dispatch(lifecycle.request('commit_restore', op, fence, {'phase': 'prepare_safety'}))
    service.dispatch(lifecycle.request('commit_restore', op, fence, {
        'phase': 'switch_validate', 'safety_ack': lifecycle.safety_ack(safety),
    }))
    result = service.dispatch(lifecycle.request('commit_restore', op, fence, {'phase': 'activate'}))
    assert result['phase'] in ('complete', 'data_restored_service_stopped')
    return op


def legacy(service, op, *, corrupt=True):
    journal = Journal(service.root, op)
    journal.value['final_health'] = {'application_started': True, 'internal_http_alive': True}
    journal.value.pop('public_ports_verified', None)
    journal.value.pop('public_endpoint_verified', None)
    if corrupt:
        journal.transition('needs_attention', error_code='PUBLIC_READINESS_UNVERIFIED',
                           public_ports_verified=False, public_endpoint_verified=False)
    else:
        journal.save()
    return journal


@pytest.fixture
def succession(fixture):
    service, docker, data = fixture
    captured, _ = lifecycle.capture(service)
    old = restore(service, captured, 2)
    current = restore(service, captured, 3)
    docker.calls.clear()
    return service, docker, data, captured, old, current


def no_docker_mutation(monkeypatch, docker):
    def prohibited(*args, **kwargs):
        pytest.fail('Historical reconciliation attempted a Docker mutation or container exec health check')
    for method in ('start', 'stop', 'restart_policy', 'create', 'remove', 'rename',
                   'create_volume', 'remove_volume', 'load_image', 'health'):
        monkeypatch.setattr(docker, method, prohibited)


def fences(service):
    return {p.name: p.read_bytes() for p in (service.root / 'fences').glob('*.json')}


def test_superseded_legacy_complete_remains_audit_and_third_restore_is_admitted(succession, monkeypatch):
    service, docker, _, captured, old, current = succession
    journal = legacy(service, old, corrupt=False)
    history = copy.deepcopy(journal.value['history'])
    active = service.active(lifecycle.INSTANCE)
    old_fences = fences(service)
    with monkeypatch.context() as patch:
        no_docker_mutation(patch, docker)
        # An old completed audit does not require a probe of any retired endpoint.
        patch.setattr(docker, 'public_health', lambda *a: pytest.fail('Historical completed audit probed an endpoint'))
        result = service.dispatch(lifecycle.request('status', old, 1))
        assert result['phase'] == 'complete'
        assert result['historical_public_readiness'] == 'unverified'
        assert result['public_endpoint_verified'] is False
        assert result['historical_warning_code'] == 'PUBLIC_READINESS_UNVERIFIED'
        assert Journal(service.root, old).value['history'] == history
        saved = journal.path.read_bytes()
        assert service.dispatch(lifecycle.request('status', old, 1)) == result
        assert journal.path.read_bytes() == saved
    assert service.active(lifecycle.INSTANCE) == active and active['operation_id'] == current
    assert fences(service) == old_fences
    assert restore(service, captured, 4)


def test_corrupted_historical_phase_repaired_with_proof_before_stale_fencing(succession, monkeypatch):
    service, docker, _, captured, old, current = succession
    journal = legacy(service, old)
    before = journal.path.read_bytes()
    history = copy.deepcopy(journal.value['history'])
    health = copy.deepcopy(journal.value['final_health'])
    active = service.active(lifecycle.INSTANCE)
    old_fences = fences(service)
    with monkeypatch.context() as patch:
        no_docker_mutation(patch, docker)
        result = service.dispatch(lifecycle.request('status', old, 1))
        assert result['phase'] == 'complete' and result['historical_status_reconciled'] is True
        assert result['historical_superseded_by'] == current
        assert result['public_endpoint_verified'] is False
        assert result['error_code'] == result['historical_warning_code'] == 'PUBLIC_READINESS_UNVERIFIED'
        value = Journal(service.root, old).value
        assert value['history'][:-1] == history
        assert value['history'][-1]['prior_journal_sha256'] == hashlib.sha256(before).hexdigest()
        assert value['history'][-1]['reason'] == 'historical_status_reconciled'
        assert value['history'][-1]['prior_error_code'] == 'PUBLIC_READINESS_UNVERIFIED'
        assert value['final_health'] == health
        saved = journal.path.read_bytes()
        assert service.dispatch(lifecycle.request('status', old, 1)) == result
        assert journal.path.read_bytes() == saved
    assert service.active(lifecycle.INSTANCE) == active and fences(service) == old_fences
    assert restore(service, captured, 4)


def test_two_bogus_histories_can_each_repair_but_unrelated_pending_remains_blocking(succession, monkeypatch):
    service, docker, _, captured, old, current = succession
    newest = restore(service, captured, 4)
    legacy(service, old)
    legacy(service, current)
    pending_op = str(uuid.uuid4())
    pending = Journal(service.root, pending_op)
    pending.create(lifecycle.request('capture', pending_op, 5), [], kind='capture')
    pending.transition('source_recovery_failed', watchdog_armed=True)
    pending_bytes = pending.path.read_bytes()
    old_fences = fences(service)
    with monkeypatch.context() as patch:
        no_docker_mutation(patch, docker)
        for op in (old, current):
            result = service.dispatch(lifecycle.request('status', op, 1))
            assert result['phase'] == 'complete' and result['historical_superseded_by'] == newest
    assert pending.path.read_bytes() == pending_bytes and fences(service) == old_fences
    with pytest.raises(VaultRewindError) as error:
        lifecycle.capture(service, fence=6)
    assert error.value.code == 'RECONCILIATION_REQUIRED'
    assert pending.path.read_bytes() == pending_bytes


def test_admin_dryrun_and_hash_checked_apply(succession, monkeypatch):
    service, docker, _, _, old, current = succession
    journal = legacy(service, old)
    before = journal.path.read_bytes()
    no_docker_mutation(monkeypatch, docker)
    proof = service.reconcile_historical_status(old)
    assert proof == {'eligible': True, 'operation_id': old, 'journal_sha256': hashlib.sha256(before).hexdigest(),
                     'superseded_by': current, 'changed': False}
    assert journal.path.read_bytes() == before
    with pytest.raises(VaultRewindError) as error:
        service.reconcile_historical_status(old, apply=True, expected_sha256='0' * 64)
    assert error.value.code == 'JOURNAL_CHANGED' and journal.path.read_bytes() == before
    result = service.reconcile_historical_status(old, apply=True, expected_sha256=proof['journal_sha256'])
    assert result['changed'] and result['status']['phase'] == 'complete'
    assert not service.reconcile_historical_status(old)['eligible']


def test_current_unverified_generation_still_blocks(fixture, monkeypatch):
    service, docker, _ = fixture
    captured, _ = lifecycle.capture(service)
    current = restore(service, captured, 2)
    journal = legacy(service, current, corrupt=False)
    docker.items[journal.value['final_id']]['NetworkSettings']['Ports'] = {}
    with monkeypatch.context() as patch:
        no_docker_mutation(patch, docker)
        result = service.dispatch(lifecycle.request('status', current, 2))
        assert result['phase'] == 'needs_attention'
        assert result['error_code'] == 'PUBLIC_PORTS_UNAVAILABLE'
        assert not service.reconcile_historical_status(current)['eligible']
    with pytest.raises(VaultRewindError) as error:
        lifecycle.capture(service, fence=3)
    assert error.value.code == 'RECONCILIATION_REQUIRED'


def test_direct_recovery_does_not_start_retired_generation(succession, monkeypatch):
    service, docker, _, _, old, current = succession
    journal = legacy(service, old)
    successor = Journal(service.root, current)
    successor.value['final_health'].pop('public_endpoint_verified')
    successor.save()
    before, active = journal.path.read_bytes(), service.active(lifecycle.INSTANCE)
    no_docker_mutation(monkeypatch, docker)
    with pytest.raises(VaultRewindError) as error:
        service.recover(old)
    assert error.value.code == 'RECONCILIATION_REQUIRED'
    assert journal.path.read_bytes() == before and service.active(lifecycle.INSTANCE) == active


def test_correct_stopped_successor_is_eligible_without_endpoint_probe(fixture, monkeypatch):
    service, docker, _ = fixture
    captured, _ = lifecycle.capture(service)
    old = restore(service, captured, 2)
    docker.stop(service.active(lifecycle.INSTANCE)['container_id'])
    current = restore(service, captured, 3)
    assert Journal(service.root, current).value['phase'] == 'data_restored_service_stopped'
    legacy(service, old)
    no_docker_mutation(monkeypatch, docker)
    monkeypatch.setattr(docker, 'public_health', lambda *a: pytest.fail('Stopped successor must not be probed'))
    assert service.reconcile_historical_status(old)['eligible']
    result = service.dispatch(lifecycle.request('status', old, 1))
    assert result['phase'] == 'complete' and result['historical_superseded_by'] == current
    assert docker.items[service.active(lifecycle.INSTANCE)['container_id']]['State']['Running'] is False


@pytest.mark.parametrize(('subject', 'keys', 'value'), [
    ('old', ('watchdog_armed',), True),
    ('old', ('watchdog_armed',), 0),
    ('old', ('error_code',), 'RESTORE_ACTIVATION_UNCERTAIN'),
    ('old', ('kind',), 'capture'),
    ('old', ('activation_started',), False),
    ('old', ('history',), []),
    ('old', ('history',), [None]),
    ('old', ('created_at',), 'invalid'),
    ('old', ('owner',), process_identity()),
    ('old', ('final_health', 'public_endpoint_verified'), True),
    ('old', ('final_health',), None),
    ('old', ('owner',), {'pid': 'invalid'}),
    ('new', ('phase',), 'needs_attention'),
    ('new', ('watchdog_armed',), True),
    ('new', ('owner',), process_identity()),
    ('new', ('created_at',), 0),
    ('new', ('instance_id',), str(uuid.uuid4())),
    ('new', ('active_generation',), str(uuid.uuid4())),
    ('new', ('history',), []),
    ('new', ('candidate_validated', 'internal_http_alive'), False),
    ('new', ('candidate_validated', 'database_integrity'), 'unknown'),
    ('new', ('final_health', 'public_endpoint_verified'), False),
    ('new', ('final_health', 'public_endpoint_count'), 0),
    ('new', ('final_health', 'public_endpoint_count'), True),
    ('new', ('public_endpoint_verified',), False),
    ('new', ('source_service_outcome',), 'unknown'),
    ('new', ('generation_steps', 0, 'phase'), 'materialized'),
    ('new', ('generation_steps', 0, 'new_identity'), [0, 0]),
    ('active', ('operation_id',), str(uuid.uuid4())),
    ('active', ('container_id',), 'f' * 64),
    ('active', ('descriptor_fingerprint',), 'f' * 64),
    ('active', ('image_id',), 'sha256:' + 'f' * 64),
    ('active', ('mounts',), []),
    ('container', ('Config', 'Labels', 'org.vaultrewind.instance'), str(uuid.uuid4())),
    ('container', ('Config', 'Labels', 'org.vaultrewind.operation'), str(uuid.uuid4())),
    ('container', ('Config', 'Labels', 'org.vaultrewind.role'), 'candidate'),
    ('container', ('Name',), '/wrong-owner'),
    ('container', ('Image',), 'sha256:' + 'f' * 64),
    ('container', ('State', 'Running'), False),
    ('container', ('State', 'Paused'), True),
    ('container', ('State', 'Restarting'), True),
    ('container', ('State', 'OOMKilled'), True),
    ('container', ('State', 'Health'), {'Status': 'unhealthy'}),
    ('container', ('NetworkSettings', 'Ports'), {}),
    ('container', ('HostConfig', 'PortBindings'), {}),
    ('container', ('HostConfig', 'NetworkMode'), 'none'),
    ('container', ('HostConfig', 'RestartPolicy'), {'Name': 'no'}),
    ('container', ('Mounts', 0, 'Source'), '/does-not-match'),
    ('container', ('Mounts', 0, 'Destination'), '/different'),
    ('container', ('Mounts', 0, 'RW'), False),
    ('container', ('Mounts', 0, 'Type'), 'volume'),
], ids=lambda x: str(x) if isinstance(x, str) else None)
def test_incomplete_or_conflicting_proof_never_releases_reservation(succession, monkeypatch, subject, keys, value):
    service, docker, _, _, old, current = succession
    old_journal = legacy(service, old)
    new_journal = Journal(service.root, current)
    active = service.active(lifecycle.INSTANCE)
    container = docker.items[new_journal.value['final_id']]
    subjects = {'old': old_journal.value, 'new': new_journal.value, 'active': active, 'container': container}
    target = subjects[subject]
    for key in keys[:-1]:
        target = target[key]
    target[keys[-1]] = value
    old_journal.save()
    new_journal.save()
    atomic_json(service.root / 'active' / (lifecycle.INSTANCE + '.json'), active)
    before, old_fences = old_journal.path.read_bytes(), fences(service)
    no_docker_mutation(monkeypatch, docker)
    proof = service.reconcile_historical_status(old)
    assert proof['eligible'] is False and proof['reason'] == 'historical_repair_unproven'
    assert old_journal.path.read_bytes() == before and fences(service) == old_fences
    # Invalid proof must not grant the narrow status bypass of live fencing.
    with pytest.raises(VaultRewindError) as error:
        service.dispatch(lifecycle.request('status', old, 1))
    assert error.value.code in ('STALE_FENCE', 'RECONCILIATION_REQUIRED')
    assert old_journal.path.read_bytes() == before and fences(service) == old_fences


def test_missing_current_container_and_unreachable_public_probe_fail_closed(succession, monkeypatch):
    service, docker, _, _, old, current = succession
    journal = legacy(service, old)
    before = journal.path.read_bytes()
    no_docker_mutation(monkeypatch, docker)
    def unavailable(*args):
        raise VaultRewindError('DOCKER_UNAVAILABLE', 'Synthetic unavailable transport')
    with monkeypatch.context() as patch:
        patch.setattr(docker, 'public_health', unavailable)
        assert not service.reconcile_historical_status(old)['eligible']
    docker.items.pop(Journal(service.root, current).value['final_id'])
    assert not service.reconcile_historical_status(old)['eligible']
    assert journal.path.read_bytes() == before


@pytest.mark.parametrize('changed', ['active', 'journal'])
def test_successor_authority_changed_during_probe_is_rejected(succession, monkeypatch, changed):
    service, docker, _, _, old, current = succession
    journal = legacy(service, old)
    before = journal.path.read_bytes()
    no_docker_mutation(monkeypatch, docker)
    actual = docker.public_health
    def probe(*args):
        result = actual(*args)
        if changed == 'active':
            active = service.active(lifecycle.INSTANCE)
            active['operation_id'] = str(uuid.uuid4())
            atomic_json(service.root / 'active' / (lifecycle.INSTANCE + '.json'), active)
        else:
            successor = Journal(service.root, current)
            successor.transition('needs_attention', error_code='PUBLIC_ENDPOINT_UNAVAILABLE')
        return result
    monkeypatch.setattr(docker, 'public_health', probe)
    assert not service.reconcile_historical_status(old)['eligible']
    assert journal.path.read_bytes() == before


def test_fixed_admin_validator_can_hold_host_lock_through_upgrade_admission(succession, monkeypatch):
    service, docker, _, _, old, _ = succession
    journal = legacy(service, old)
    before = journal.path.read_bytes()
    no_docker_mutation(monkeypatch, docker)
    with Locks(service.root, []):
        assert service.historical_status_evidence_locked(old)['eligible']
        # The bootstrap can run the reviewed installer here without releasing the lock.
        # Another helper cannot acquire it; no nested locking wrapper is used.
        with pytest.raises(VaultRewindError) as error, Locks(service.root, []):
            pytest.fail('Host lock was not held')
        assert error.value.code == 'RESOURCE_BUSY'
    assert journal.path.read_bytes() == before


@pytest.mark.parametrize(('key', 'value'), [('Driver', 'remote'), ('Options', {'device': '/unapproved'}),
                                           ('Scope', 'global'), ('Mountpoint', '/unapproved')])
def test_named_volume_successor_requires_exact_local_provenance(fixture, monkeypatch, key, value):
    service, docker, data = fixture
    mount = service.policy.value['instances'][lifecycle.INSTANCE]['mounts'][0]
    mount.update(type='volume', volume_name='original-volume')
    docker.items[lifecycle.CID]['Mounts'][0].update(Type='volume', Name='original-volume')
    docker.volumes['original-volume'] = {'Name': 'original-volume', 'Mountpoint': str(data), 'Driver': 'local',
                                         'Scope': 'local', 'Options': {}, 'Labels': {}}
    captured, _ = lifecycle.capture(service)
    old = restore(service, captured, 2)
    restore(service, captured, 3)
    journal = legacy(service, old)
    before = journal.path.read_bytes()
    no_docker_mutation(monkeypatch, docker)
    assert service.reconcile_historical_status(old)['eligible']
    name = service.active(lifecycle.INSTANCE)['mounts'][0]['volume_name']
    assert Path(docker.volumes[name]['Mountpoint']).is_dir()
    docker.volumes[name][key] = value
    assert not service.reconcile_historical_status(old)['eligible']
    assert journal.path.read_bytes() == before


@pytest.mark.parametrize('defect', ['running', 'restart', 'ports', 'start_requested'])
def test_stopped_successor_exemption_requires_actual_intent_and_state(fixture, monkeypatch, defect):
    service, docker, _ = fixture
    captured, _ = lifecycle.capture(service)
    old = restore(service, captured, 2)
    docker.stop(service.active(lifecycle.INSTANCE)['container_id'])
    current = restore(service, captured, 3)
    journal = legacy(service, old)
    new_journal = Journal(service.root, current)
    item = docker.items[new_journal.value['final_id']]
    if defect == 'running':
        item['State']['Running'] = True
    elif defect == 'restart':
        item['HostConfig']['RestartPolicy']['Name'] = 'always'
    elif defect == 'ports':
        item['NetworkSettings']['Ports'] = copy.deepcopy(lifecycle.PORTS)
    else:
        new_journal.value['start_on_completion'] = True
        new_journal.save()
    before = journal.path.read_bytes()
    no_docker_mutation(monkeypatch, docker)
    assert not service.reconcile_historical_status(old)['eligible']
    assert journal.path.read_bytes() == before

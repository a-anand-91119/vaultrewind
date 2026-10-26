"""Pure gates and product-planner tests. Only in-memory fixture SQL; no live I/O."""
from __future__ import annotations

import copy
import json
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import prove_drive_retention as drill
from vaultrewind.server.db import Base, make_engine, sessions
from vaultrewind.server.models import BackupPolicy, Instance, Job, Repository, Snapshot, SnapshotCopy
from vaultrewind.server.policy import retention_preview

DEST = '81be8f91-7e7c-4531-9ceb-740d4239aa15'
RUN = 'fe65591b-4451-4df0-94c1-29a3cec7cb11'
CURRENT = datetime(2040, 1, 31, 12, tzinfo=UTC)


def arguments(*extra):
    return drill.parse_args(['--dedicated-test-account', '--destination-id', DEST, '--run-id', RUN,
                             '--planner-time', CURRENT.isoformat(), *extra])


def forbidden(*_args, **_kwargs):
    pytest.fail('Parked drill attempted private or external I/O.')


@pytest.fixture
def catalog():
    engine = make_engine('sqlite:///:memory:')
    Base.metadata.create_all(engine)
    factory = sessions(engine)
    repos, records = drill.fixture_records(CURRENT, DEST)
    for record in records:
        record['manifest_hash'] = drill.digest({'manifest': record['snapshot_id']})
        record['restic_snapshot_id'] = drill.digest({'copy': record['copy_id']})
    drill.seed_catalog(factory, repos, records, DEST)
    yield factory, repos, records
    engine.dispose()


def preview(catalog, current=CURRENT):
    factory, repos, _ = catalog
    with factory() as db:
        return retention_preview(db, repos[0]['instance_id'], current=current)


def record(catalog, label):
    return next(r for r in catalog[2] if r['label'] == label)


@pytest.mark.parametrize('flags', [[], ['--root-go', drill.RELEASE]])
def test_default_is_pure_even_with_release_word(flags, monkeypatch, capsys):
    monkeypatch.setattr(drill, 'RetentionDrill', forbidden)
    monkeypatch.setattr(drill, 'private_read', forbidden)
    monkeypatch.setattr(drill, 'private_write', forbidden)
    monkeypatch.setattr(Path, 'mkdir', forbidden)
    assert drill.main(flags) == 0
    result = json.loads(capsys.readouterr().out)
    assert result['status'] == 'prepared_not_run_drive_parked'
    assert result['private_files_opened'] == result['network_sql_provider_ssh_docker_calls'] == 0
    assert result['evidence_written'] is False and result['retention_live_proven'] is False
    assert result['AC14_release_verified'] is False


@pytest.mark.parametrize('field,value', [('execute', False), ('root_go', 'ROOTGO'), ('root_go', ''),
                                      ('dedicated_test_account', False), ('destination_id', None),
                                      ('run_id', None), ('planner_time', None)])
def test_every_execution_condition_precedes_runtime_io(field, value, monkeypatch):
    args = arguments('--execute', '--root-go', drill.RELEASE)
    setattr(args, field, value)
    monkeypatch.setattr(drill, 'private_read', forbidden)
    monkeypatch.setattr(drill, 'private_write', forbidden)
    monkeypatch.setattr(Path, 'mkdir', forbidden)
    with pytest.raises(drill.DrillError, match='DRIVE_PARKED'):
        drill.RetentionDrill(args)


def test_execute_without_full_scope_does_not_construct_runtime(monkeypatch, capsys):
    monkeypatch.setattr(drill, 'RetentionDrill', forbidden)
    monkeypatch.setattr(drill.os, 'umask', forbidden)
    assert drill.main(['--execute', '--root-go', drill.RELEASE]) == 1
    assert 'DRIVE_PARKED' in capsys.readouterr().out


def test_all_execution_flags_are_accepted_without_doing_work():
    drill.require_execution(arguments('--execute', '--root-go', drill.RELEASE))


@pytest.mark.parametrize('value', ['../source', DEST.upper(), '00000000-0000-0000-0000-000000000000',
                                  '46ac8eb9-1854-1fc6-924f-af14c6b7d0c2'])
def test_uuid_selection_is_exact_and_version_four(value):
    with pytest.raises(Exception) as error:
        drill.identifier(value)
    assert error.type.__name__ == 'ArgumentTypeError'


@pytest.mark.parametrize('value', ['2040-01-31T12:00:00', '2040-01-31T12:00:00+05:30', 'not-time'])
def test_fixture_clock_must_be_explicit_utc(value):
    with pytest.raises(Exception) as error:
        drill.planner_time(value)
    assert error.type.__name__ == 'ArgumentTypeError'


def test_fixture_ids_are_new_and_cannot_select_native_scope():
    repos, records = drill.fixture_records(CURRENT, DEST)
    drill.guard_new_scope(repos, records, set())
    for collision in (repos[0]['instance_id'], repos[1]['id'], records[0]['copy_id'], records[0]['snapshot_id']):
        with pytest.raises(drill.DrillError, match='MUST_ALL_BE_NEW'):
            drill.guard_new_scope(repos, records, {collision})
    repos[0]['instance_id'] = drill.SOURCE_ID
    with pytest.raises(drill.DrillError, match='MUST_ALL_BE_NEW'):
        drill.guard_new_scope(repos, records, set())


def test_fixture_copy_cannot_cross_repository_instance_boundary():
    repos, records = drill.fixture_records(CURRENT, DEST)
    records[0]['repository_id'] = repos[1]['id']
    with pytest.raises(drill.DrillError, match='OUTSIDE_NEW_SCOPE'):
        drill.guard_new_scope(repos, records, set())


def test_product_rolls_utc_days_and_keeps_every_point_on_or_within_boundary(catalog):
    plan = preview(catalog)
    assert plan['copy_ids'] == [record(catalog, 'expired')['copy_id']]
    assert plan['cutoff'] == (CURRENT - timedelta(days=30)).isoformat()
    entries = {e['copy_id']: e for e in plan['entries']}
    for label in ('boundary', 'within_one', 'within_two'):
        entry = entries[record(catalog, label)['copy_id']]
        assert entry['eligible'] is False
    assert 'newest_complete' in entries[record(catalog, 'newest')['copy_id']]['protections']
    assert 'pin' in entries[record(catalog, 'pinned')['copy_id']]['protections']
    assert record(catalog, 'other_instance')['copy_id'] not in entries


def test_second_fixture_time_proves_newest_protection_even_when_every_point_is_old(catalog):
    factory, repos, records = catalog
    original_times = {r['snapshot_id']: r['captured_at'] for r in records}
    first = record(catalog, 'expired')
    with factory.begin() as db:
        db.get(SnapshotCopy, first['copy_id']).state = 'expired'
    first['expired'] = True
    plan = preview(catalog, CURRENT + timedelta(days=31))
    assert set(plan['copy_ids']) == {record(catalog, name)['copy_id']
                                    for name in ('boundary', 'within_one', 'within_two')}
    assert record(catalog, 'newest')['copy_id'] not in plan['copy_ids']
    assert record(catalog, 'pinned')['copy_id'] not in plan['copy_ids']
    assert all(r['captured_at'] == original_times[r['snapshot_id']] for r in records)
    with factory() as db:
        for snapshot_id, captured in original_times.items():
            assert db.get(Snapshot, snapshot_id).captured_at.replace(tzinfo=UTC).isoformat() == captured
        assert db.get(Repository, repos[1]['id']).instance_id == repos[1]['instance_id']


@pytest.mark.parametrize('cause', ['degraded', 'uncertain', 'imported', 'overdue', 'failed'])
def test_real_product_failure_conditions_freeze_all_deletions(catalog, cause):
    factory, repos, _ = catalog
    with factory.begin() as db:
        if cause == 'degraded':
            db.get(Instance, repos[0]['instance_id']).backup_health = 'degraded'
        elif cause == 'uncertain':
            db.get(Repository, repos[0]['id']).health = 'unknown'
        elif cause == 'imported':
            db.get(Repository, repos[0]['id']).imported = True
        elif cause == 'overdue':
            from sqlalchemy import select
            policy = db.scalar(select(BackupPolicy).where(BackupPolicy.instance_id == repos[0]['instance_id']))
            policy.enabled = True
            policy.next_run_at = CURRENT - timedelta(seconds=1)
        else:
            db.add(Job(kind='backup', instance_id=repos[0]['instance_id'], state='failed',
                       idempotency_scope='fixture', idempotency_key='failure', request_hash='0' * 64, request={}))
    plan = preview(catalog)
    assert plan['frozen'] and plan['copy_ids'] == [] and plan['freeze_reasons']
    with pytest.raises(drill.DrillError, match='FROZEN'):
        drill.exact_deletions(plan, copy.deepcopy(plan), catalog[2], repos[0])


def test_exact_copy_mapping_returns_only_full_planned_restic_ids(catalog):
    plan = preview(catalog)
    assert drill.exact_deletions(plan, copy.deepcopy(plan), catalog[2], catalog[1][0]) == [
        record(catalog, 'expired')['restic_snapshot_id']]


@pytest.mark.parametrize('change', ['revision', 'pin', 'extra_copy', 'other_instance', 'short_id', 'alias'])
def test_changed_protected_or_broadened_deletion_set_is_rejected(catalog, change):
    plan = preview(catalog)
    again = copy.deepcopy(plan)
    if change == 'revision':
        again['policy_revision'] += 1
    elif change == 'pin':
        again['entries'][0]['protections'].append('pin')
    elif change == 'extra_copy':
        plan['copy_ids'].append(record(catalog, 'newest')['copy_id'])
        again = copy.deepcopy(plan)
    elif change == 'other_instance':
        record(catalog, 'expired')['repository_id'] = catalog[1][1]['id']
    elif change == 'short_id':
        record(catalog, 'expired')['restic_snapshot_id'] = 'abcd1234'
    elif change == 'alias':
        extra = record(catalog, 'boundary')
        extra['restic_snapshot_id'] = record(catalog, 'expired')['restic_snapshot_id']
        entry = next(e for e in plan['entries'] if e['copy_id'] == extra['copy_id'])
        entry['eligible'] = True
        plan['copy_ids'].append(extra['copy_id'])
        again = copy.deepcopy(plan)
    with pytest.raises(drill.DrillError):
        drill.exact_deletions(plan, again, catalog[2], catalog[1][0])


def provider_listing(records, repo):
    return [{'restic_snapshot_id': r['restic_snapshot_id'], 'instance_uuid': r['instance_id'],
             'snapshot_uuid': r['snapshot_id'], 'manifest_hash': r['manifest_hash']}
            for r in records if r['repository_id'] == repo['id'] and not r.get('expired')]


@pytest.mark.parametrize('change', ['unknown', 'missing', 'foreign_instance', 'wrong_manifest'])
def test_provider_set_must_match_catalog_exactly(catalog, change):
    _, repos, records = catalog
    listing = provider_listing(records, repos[0])
    drill.verify_provider_set(listing, records, repos[0])
    if change == 'unknown':
        listing.append(provider_listing(records, repos[1])[0])
    elif change == 'missing':
        listing.pop()
    elif change == 'foreign_instance':
        listing[0]['instance_uuid'] = repos[1]['instance_id']
    else:
        listing[0]['manifest_hash'] = 'f' * 64
    with pytest.raises(drill.DrillError):
        drill.verify_provider_set(listing, records, repos[0])


@pytest.mark.parametrize('changes', [{'retained': ['a' * 64]}, {'removed': []}, {'complete': False},
                                    {'exit_code': 1}, {'already_absent': ['a' * 64]},
                                    {'error_code': 'STORAGE_DELETE_DENIED'}, {'requested': ['b' * 64]}])
def test_deletion_denial_absence_or_ambiguous_result_never_passes(changes):
    wanted = ['a' * 64]
    result = {'complete': True, 'exit_code': 0, 'error_code': None, 'requested': wanted,
              'removed': wanted, 'retained': [], 'already_absent': []}
    drill.verify_forget_result(result, wanted)
    with pytest.raises(drill.DrillError, match='DELETION_NOT_PROVEN'):
        drill.verify_forget_result({**result, **changes}, wanted)


@pytest.mark.parametrize('failure', [None, 'delete_denied', 'lost_delete_response', 'full_check_failed'])
def test_live_round_orders_exact_deletion_and_stops_on_uncertainty(catalog, failure):
    factory, repos, records = catalog
    events = []
    provider = provider_listing(records, repos[0])

    class RecordingRepository:
        def describe(self):
            events.append('describe')

        def list_snapshots(self):
            return copy.deepcopy(provider)

        def forget(self, ids):
            events.append(('forget', ids))
            if failure == 'delete_denied':
                return {'complete': False, 'exit_code': 1, 'requested': ids, 'removed': [],
                        'retained': ids, 'already_absent': [], 'error_code': 'STORAGE_DELETE_DENIED'}
            provider[:] = [r for r in provider if r['restic_snapshot_id'] not in ids]
            if failure == 'lost_delete_response':
                raise drill.DrillError('STORAGE_TIMEOUT')
            return {'complete': True, 'exit_code': 0, 'error_code': None, 'requested': ids,
                    'removed': ids, 'retained': [], 'already_absent': []}

        def prune(self, verify):
            assert verify is True
            events.append('prune')
            return {'pruned': True, 'check': {'ok': True}}

        def check(self, read_data):
            assert read_data is True
            events.append('full-check')
            return {'ok': failure != 'full_check_failed', 'full_data_verified': failure != 'full_check_failed'}

    @contextmanager
    def repository(selected):
        assert selected == repos[0]
        yield RecordingRepository()

    def readback(selected, item, phase):
        assert selected == repos[0] and not item.get('expired')
        events.append(('readback', item['label']))
        return {'copy_id': item['copy_id']}

    runner = object.__new__(drill.RetentionDrill)
    runner.state = {'repositories': repos, 'records': records, 'rounds': []}
    runner.repository, runner.readback = repository, readback
    runner.guard = lambda: events.append('guard')
    runner.save = lambda: events.append('save')
    if failure:
        with pytest.raises(drill.DrillError):
            runner.expire(factory, CURRENT, {'expired'}, 'rolling-boundary')
        assert runner.state['rounds'][0]['forget_attempted'] is True
        assert not runner.state['rounds'][0].get('complete')
        assert sum(isinstance(e, tuple) and e[0] == 'forget' for e in events) == 1
        assert not any(isinstance(e, tuple) and e[0] == 'readback' for e in events)
        if failure != 'full_check_failed':
            assert 'prune' not in events
        with factory() as db:
            assert db.get(SnapshotCopy, record(catalog, 'expired')['copy_id']).state == 'complete'
        return
    runner.expire(factory, CURRENT, {'expired'}, 'rolling-boundary')
    forgotten = record(catalog, 'expired')['restic_snapshot_id']
    assert ('forget', [forgotten]) in events
    assert events.index('save') < events.index(('forget', [forgotten])) < events.index('prune')
    assert events.index('prune') < events.index('full-check')
    assert {e[1] for e in events if isinstance(e, tuple) and e[0] == 'readback'} == {
        'boundary', 'within_one', 'within_two', 'pinned', 'newest'}
    assert runner.state['rounds'][0]['complete'] is True
    with factory() as db:
        assert db.get(SnapshotCopy, record(catalog, 'expired')['copy_id']).state == 'expired'
        assert db.get(SnapshotCopy, record(catalog, 'other_instance')['copy_id']).state == 'complete'


def test_no_public_success_report_can_be_created_from_preparation(monkeypatch):
    runner = object.__new__(drill.RetentionDrill)
    runner.args = SimpleNamespace(run_id=RUN, destination_id=DEST)
    runner.state = {'status': 'prepared_not_run', 'rounds': []}
    monkeypatch.setattr(Path, 'write_text', forbidden)
    monkeypatch.setattr(drill, 'private_write', forbidden)
    with pytest.raises(drill.DrillError, match='NO_UNEXECUTED_SUCCESS'):
        runner.publish()

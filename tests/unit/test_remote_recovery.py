"""Recovery must outlive Docker availability and a single unsuccessful attempt."""
from types import SimpleNamespace
from uuid import uuid4

import pytest

from vaultrewind.core.errors import VaultRewindError
from vaultrewind.remote import recovery
from vaultrewind.remote.journal import Journal, atomic_json
from vaultrewind.remote.recovery import SystemdRecovery, watchdog_loop


def test_watchdog_retries_returned_failure_and_transport_exception_until_disarmed(tmp_path, monkeypatch):
    op = str(uuid4())
    path = tmp_path / 'journals' / (op + '.json')
    atomic_json(path, {'operation_id': op, 'watchdog_armed': True, 'owner': None, 'phase': 'quiescing'})
    calls, sleeps = [], []
    def recover(operation, reason):
        calls.append((operation, reason))
        if len(calls) == 2:
            raise VaultRewindError('DOCKER_UNAVAILABLE', 'Synthetic daemon outage')
        value = Journal(tmp_path, op).value
        value.update(phase='failed_safe' if len(calls) == 8 else 'source_recovery_failed', watchdog_armed=len(calls) != 8)
        atomic_json(path, value)
    monkeypatch.setattr(recovery, 'expired', lambda _: True)
    monkeypatch.setattr(recovery.time, 'sleep', sleeps.append)
    watchdog_loop(SimpleNamespace(root=tmp_path, recover=recover), op)
    assert calls == [(op, 'deadline')] * 8
    assert sleeps == [2, 4, 8, 16, 30, 30, 30]
    assert Journal(tmp_path, op).value['phase'] == 'failed_safe'


def test_resume_watchdog_preserves_expired_deadline_and_owner(tmp_path, monkeypatch):
    op = str(uuid4())
    value = {'operation_id': op, 'watchdog_armed': True, 'deadline': 123, 'owner': {'pid': 42}}
    atomic_json(tmp_path / 'journals' / (op + '.json'), value)
    calls = []
    monkeypatch.setattr(SystemdRecovery, '_run', staticmethod(lambda args, **kwargs: calls.append(args)))
    SystemdRecovery().resume(Journal(tmp_path, op))
    assert Journal(tmp_path, op).value == value
    assert calls == [['start', f'vaultrewind-watchdog@{op}.service'],
                     ['is-active', '--quiet', f'vaultrewind-watchdog@{op}.service']]


@pytest.mark.parametrize('dependency', ['docker.service', 'docker.socket'])
def test_verify_rejects_watchdog_stop_dependency(monkeypatch, dependency):
    def run(args, **kwargs):
        value = dependency.encode() if '--property=Requires' in args else b'loaded\n'
        return SimpleNamespace(returncode=0, stdout=value)
    monkeypatch.setattr(SystemdRecovery, '_run', staticmethod(run))
    with pytest.raises(VaultRewindError) as error:
        SystemdRecovery().verify()
    assert error.value.code == 'WATCHDOG_UNAVAILABLE'


@pytest.mark.parametrize('recover_raises', [True, False])
def test_boot_reconciler_starts_independent_watchdog_before_first_attempt(tmp_path, monkeypatch, recover_raises):
    from vaultrewind.remote import helper
    op = str(uuid4())
    atomic_json(tmp_path / 'journals' / (op + '.json'), {'operation_id': op, 'watchdog_armed': True})
    calls = []
    def recover(operation, reason):
        calls.append(('recover', operation, reason))
        if recover_raises:
            raise VaultRewindError('DOCKER_UNAVAILABLE', 'Synthetic daemon outage')
        return {'phase': 'source_recovery_failed'}
    service = SimpleNamespace(root=tmp_path, recover=recover,
                              recovery=SimpleNamespace(resume=lambda journal: calls.append(('resume', journal.value['operation_id']))))
    monkeypatch.setattr(helper.Policy, 'load', lambda: None)
    monkeypatch.setattr(helper, 'Helper', lambda _: service)
    monkeypatch.setattr(helper.sys, 'argv', ['helper', '--reconcile-all'])
    assert helper.main() == (1 if recover_raises else 0)
    assert calls == [('resume', op), ('recover', op, 'boot')]

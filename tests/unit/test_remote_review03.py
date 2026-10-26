"""Independent review regressions; Docker/systemd unit doubles are explicit."""
import json
from pathlib import Path

import pytest

from tests.unit import test_remote_lifecycle as lifecycle
from vaultrewind.core.errors import VaultRewindError
from vaultrewind.remote.docker import Docker
from vaultrewind.remote.journal import Journal

fixture = lifecycle.fixture


def test_running_restore_requires_public_endpoint_but_stopped_profile_does_not(fixture):
    service, docker, _ = fixture
    policy = service.policy.value['instances'][lifecycle.INSTANCE]
    policy['port_bindings'] = {}
    docker.items[lifecycle.CID]['HostConfig']['PortBindings'] = {}
    docker.items[lifecycle.CID]['NetworkSettings']['Ports'] = {}
    enrolled = service.policy.instance(lifecycle.INSTANCE)
    ready = service.restore_readiness(enrolled, service.inspect(enrolled))
    assert not ready['restore_ready'] and ready['restore_error_code'] == 'PUBLIC_ENDPOINT_REQUIRED'
    with pytest.raises(VaultRewindError) as error:
        Docker().public_health('unused', {}, 0)
    assert error.value.code == 'PUBLIC_ENDPOINT_REQUIRED'
    docker.items[lifecycle.CID]['State']['Running'] = False
    view = service.inspect(enrolled)
    assert service.restore_readiness(enrolled, view)['restore_ready']
    with pytest.raises(VaultRewindError) as error:
        service.restore_readiness(enrolled, view, required=True, start_on_completion=True)
    assert error.value.code == 'PUBLIC_ENDPOINT_REQUIRED'


def test_activation_recovery_repairs_and_verifies_restart_before_complete(fixture, monkeypatch):
    service, docker, _ = fixture
    cap, _ = lifecycle.capture(service)
    op = lifecycle.stage(service, cap)
    lifecycle.switch(service, op, lifecycle.prepare(service, op))
    actual_update = docker.restart_policy
    def crash(cid, policy):
        if docker.items[cid]['Config'].get('Labels', {}).get('org.vaultrewind.role') == 'active':
            raise VaultRewindError('DOCKER_UNAVAILABLE', 'Synthetic crash before restart update')
        return actual_update(cid, policy)
    with monkeypatch.context() as patch:
        patch.setattr(docker, 'restart_policy', crash)
        with pytest.raises(VaultRewindError):
            service.dispatch(lifecycle.request('commit_restore', op, 2, {'phase': 'activate'}))
    value = Journal(service.root, op).value
    final = value['final_id']
    assert docker.items[final]['HostConfig']['RestartPolicy']['Name'] == 'no'
    # A silently ineffective Docker update must not produce complete either.
    with monkeypatch.context() as patch:
        patch.setattr(docker, 'restart_policy', lambda *a: None)
        assert service.recover(op)['phase'] == 'needs_attention'
    result = service.recover(op)
    assert result['phase'] == 'complete'
    assert docker.items[final]['HostConfig']['RestartPolicy']['Name'] == value['restore_descriptor']['host_config']['RestartPolicy']['Name']
    assert not docker.inspect(value['candidate_id'], missing=True)


def test_overlay_updates_only_private_generation_and_checks_effective_url(fixture):
    service, _docker, data = fixture
    original = {'domain': 'https://source.synthetic.invalid', 'signups_allowed': False}
    source = data / 'config.json'
    source.write_text(json.dumps(original))
    source.chmod(0o600)
    cap, _ = lifecycle.capture(service)
    policy = service.policy.value['instances'][lifecycle.INSTANCE]
    policy['recovery_profile'] = {'environment': {'DOMAIN': 'https://target.synthetic.invalid/'}, 'revision': 2}
    op = lifecycle.stage(service, cap)
    journal = Journal(service.root, op).value
    config = Path(journal['generation_steps'][0]['new']) / 'config.json'
    assert json.loads(config.read_text()) == {**original, 'domain': 'https://target.synthetic.invalid'}
    assert config.stat().st_mode & 0o777 == 0o600
    assert json.loads(source.read_text()) == original
    captured = service.root / 'operations' / cap / 'capture' / 'data' / 'config.json'
    assert json.loads(captured.read_text()) == original
    staged = service.root / 'operations' / op / 'restore' / 'data' / 'config.json'
    assert json.loads(staged.read_text()) == original
    lifecycle.switch(service, op, lifecycle.prepare(service, op))
    live = data / 'config.json'
    live.write_text(json.dumps(original))
    with pytest.raises(VaultRewindError) as error:
        service.dispatch(lifecycle.request('commit_restore', op, 2, {'phase': 'activate'}))
    assert error.value.code == 'TARGET_CONFIG_MISMATCH'
    assert not Journal(service.root, op).value.get('activation_started')


def test_unknown_environment_overlay_fails_without_echoing_secret(fixture):
    service, _docker, _data = fixture
    cap, _ = lifecycle.capture(service)
    service.policy.value['instances'][lifecycle.INSTANCE]['recovery_profile'] = {'environment': {'ADMIN_TOKEN': 'synthetic-not-for-errors'}}
    with pytest.raises(VaultRewindError) as error:
        lifecycle.stage(service, cap)
    assert error.value.code == 'TARGET_OVERLAY_UNSUPPORTED'
    assert 'synthetic-not-for-errors' not in str(error.value)


def test_repeated_named_volume_restore_cleans_exact_prior_after_grace(fixture):
    service, docker, data = fixture
    mount = service.policy.value['instances'][lifecycle.INSTANCE]['mounts'][0]
    mount.update(type='volume', volume_name='original-volume')
    docker.items[lifecycle.CID]['Mounts'][0].update(Type='volume', Name='original-volume')
    docker.volumes['original-volume'] = {'Name': 'original-volume', 'Mountpoint': str(data), 'Driver': 'local', 'Scope': 'local', 'Options': {}, 'Labels': {}}
    cap, _ = lifecycle.capture(service)
    first = lifecycle.stage(service, cap)
    lifecycle.switch(service, first, lifecycle.prepare(service, first))
    service.dispatch(lifecycle.request('commit_restore', first, 2, {'phase': 'activate'}))
    previous = service.active(lifecycle.INSTANCE)['mounts'][0]['volume_name']
    j = Journal(service.root, first)
    with pytest.raises(VaultRewindError) as error:
        service.cleanup_generations(service.policy.instance(lifecycle.INSTANCE), j)
    assert error.value.code == 'CLEANUP_GRACE_PERIOD'
    assert 'original-volume' in docker.volumes and previous in docker.volumes
    j.value['rollback_cleanup_after'] = 0
    j.save()
    service.cleanup_generations(service.policy.instance(lifecycle.INSTANCE), j)
    assert 'original-volume' not in docker.volumes
    second = lifecycle.stage(service, cap, fence=3)
    safety = service.dispatch(lifecycle.request('commit_restore', second, 3, {'phase': 'prepare_safety'}))
    service.dispatch(lifecycle.request('commit_restore', second, 3, {'phase': 'switch_validate', 'safety_ack': lifecycle.safety_ack(safety)}))
    service.dispatch(lifecycle.request('commit_restore', second, 3, {'phase': 'activate'}))
    latest = service.active(lifecycle.INSTANCE)['mounts'][0]['volume_name']
    j = Journal(service.root, second)
    assert j.value['generation_steps'][0]['mount']['volume_name'] == previous
    assert not docker.inspect(j.value['candidate_id'], missing=True)
    assert previous in docker.volumes and latest in docker.volumes
    j.value['rollback_cleanup_after'] = 0
    j.save()
    for _ in range(2):
        assert service.cleanup_generations(service.policy.instance(lifecycle.INSTANCE), j)['generations_cleaned']
    assert previous not in docker.volumes and latest in docker.volumes


def test_legacy_zero_endpoint_success_is_not_trusted_even_with_boolean_proof(fixture):
    service, docker, _ = fixture
    cap, _ = lifecycle.capture(service)
    op = lifecycle.stage(service, cap)
    lifecycle.switch(service, op, lifecycle.prepare(service, op))
    service.dispatch(lifecycle.request('commit_restore', op, 2, {'phase': 'activate'}))
    journal = Journal(service.root, op)
    journal.value['restore_descriptor']['host_config']['PortBindings'] = {}
    journal.value['final_health'] = {'public_endpoint_verified': True, 'public_endpoint_count': 0}
    journal.save()
    docker.calls.clear()
    result = service.dispatch(lifecycle.request('status', op, 2))
    assert result['phase'] == 'needs_attention' and result['error_code'] == 'PUBLIC_ENDPOINT_REQUIRED'
    assert not docker.calls

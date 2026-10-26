"""Focused detached Docker readiness and sanitized transport-diagnostic regressions."""
import http.client

import pytest

from vaultrewind.core.errors import VaultRewindError
from vaultrewind.remote import docker as implementation
from vaultrewind.remote.docker import Docker


@pytest.mark.parametrize('state,error_code', [
    ({'Running':False,'ExitCode':0}, None),
    ({'Running':True,'ExitCode':0}, 'DOCKER_UNAVAILABLE'),
    ({'Running':False,'ExitCode':137}, 'SOURCE_UNCLEAN_STOP'),
    ({'Running':False,'ExitCode':0,'OOMKilled':True}, 'SOURCE_UNCLEAN_STOP'),
])
def test_stop_ack_loss_requires_proven_clean_exit_without_repeating_stop(monkeypatch, state, error_code):
    docker = Docker()
    calls = []
    def api(method, path, **_kwargs):
        calls.append((method,path))
        raise VaultRewindError('DOCKER_UNAVAILABLE','Synthetic lost acknowledgement',operation_category='containers_stop',transport_kind='timeout')
    monkeypatch.setattr(docker,'api',api)
    monkeypatch.setattr(docker,'inspect',lambda _ident:{'State':state})
    if error_code:
        with pytest.raises(VaultRewindError) as error:
            docker.stop('exact-container-id')
        assert error.value.code == error_code
    else:
        docker.stop('exact-container-id')
    assert calls == [('POST','/containers/exact-container-id/stop?t=30')]


@pytest.mark.parametrize('fast_exit', [True, False])
def test_probe_detaches_then_polls_completion_without_attaching(monkeypatch, fast_exit):
    docker = Docker()
    calls = []
    states = iter([{'Running': False, 'ExitCode': 0}] if fast_exit else
                   [{'Running': True, 'ExitCode': 0}, {'Running': True, 'ExitCode': 0}, {'Running': False, 'ExitCode': 0}])
    monkeypatch.setattr(docker, 'inspect', lambda _: {'State': {'Running': True, 'Health': {'Status': 'starting'}}})
    monkeypatch.setattr(implementation.time, 'sleep', lambda _: None)
    def api(method, path, body=None, **kwargs):
        calls.append((method, path, body))
        if path.endswith('/exec'):
            assert body['AttachStdout'] is False and body['AttachStderr'] is False
            assert body['Cmd'] == ['curl', '--fail', '--silent', '--max-time', '3', 'http://127.0.0.1:80/alive']
            return {'Id': 'test-exec'}
        if path.endswith('/start'):
            assert body == {'Detach': True, 'Tty': False}
            return None
        assert method == 'GET' and path == '/exec/test-exec/json'
        return next(states)
    monkeypatch.setattr(docker, 'api', api)
    result = docker.health('test-container', 1)
    assert result['internal_http_alive']
    assert sum(path.endswith('/json') for _, path, _ in calls) == (1 if fast_exit else 3)


@pytest.mark.parametrize('running,exit_code', [(True, 0), (False, 7)])
def test_probe_never_accepts_running_or_failed_exec_and_honors_deadline(monkeypatch, running, exit_code):
    docker = Docker()
    clock = [0.0]
    monkeypatch.setattr(implementation.time, 'monotonic', lambda: clock[0])
    monkeypatch.setattr(implementation.time, 'sleep', lambda seconds: clock.__setitem__(0, clock[0] + seconds))
    monkeypatch.setattr(docker, 'inspect', lambda _: {'State': {'Running': True}})
    def api(method, path, body=None, **kwargs):
        if path.endswith('/exec'):
            return {'Id': 'test-exec'}
        if path.endswith('/start'):
            assert body['Detach'] is True
            return None
        return {'Running': running, 'ExitCode': exit_code}
    monkeypatch.setattr(docker, 'api', api)
    with pytest.raises(VaultRewindError) as error:
        docker.health('test-container', 0.2)
    assert error.value.code == 'APPLICATION_NOT_READY'
    assert 0.2 <= clock[0] < 0.3


@pytest.mark.parametrize('method,path,category', [
    ('POST', '/exec/private-exec-id/start?secret=private-query', 'exec_start'),
    ('GET', '/exec/private-exec-id/json', 'exec_inspect'),
    ('POST', '/containers/private-container/stop?t=30', 'containers_stop'),
    ('POST', '/containers/private-container/exec', 'exec_create'),
    ('GET', '/private-host-path/secret/config', 'docker_request'),
])
@pytest.mark.parametrize('exception,kind', [(TimeoutError, 'timeout'), (http.client.BadStatusLine, 'http_protocol'),
                                          (OSError, 'os_error'), (ValueError, 'invalid_response')])
def test_transport_details_use_only_fixed_categories(monkeypatch, method, path, category, exception, kind):
    closed = []
    class BrokenConnection:
        def __init__(self, *args):
            pass
        def request(self, *args, **kwargs):
            raise exception('private-stderr-secret')
        def close(self):
            closed.append(True)
    monkeypatch.setattr(implementation, 'UnixConnection', BrokenConnection)
    with pytest.raises(VaultRewindError) as error:
        Docker().api(method, path)
    assert error.value.code == 'DOCKER_UNAVAILABLE'
    assert error.value.details == {'operation_category': category, 'transport_kind': kind}
    assert 'private' not in str(error.value) + repr(error.value.details)
    assert error.value.__suppress_context__ and closed == [True]


def published(bindings, *, running=True):
    return {'State': {'Running': running}, 'NetworkSettings': {'Ports': bindings}}


def binding(host='127.0.0.1', port='18103'):
    return {'80/tcp': [{'HostIp': host, 'HostPort': port}]}


@pytest.mark.parametrize('host', ['localhost', 'example.invalid', '192.0.2.1', '::ffff:127.0.0.1', '::1%lo', 'http://127.0.0.1'])
def test_public_probe_rejects_nonlocal_or_nonliteral_address_before_network(monkeypatch, host):
    monkeypatch.setattr(implementation.socket, 'create_connection', lambda *a, **k: pytest.fail('Must not connect'))
    with pytest.raises(VaultRewindError):
        implementation.normalized_ports(binding(host))


@pytest.mark.parametrize('expected,actual,accepted', [
    (binding(''), binding('0.0.0.0'), True),
    (binding('0.0.0.0'), binding(''), True),
    (binding('::1'), binding('0:0:0:0:0:0:0:1'), True),
    (binding(), {}, False),
    (binding(), binding('0.0.0.0'), False),
    (binding(), binding('::'), False),
    (binding('::1'), binding('::'), False),
    (binding('0.0.0.0'), binding('::'), False),
    (binding(), binding(port='18104'), False),
    ({}, binding(), False),
])
def test_actual_port_map_must_cover_without_widening_policy(expected, actual, accepted):
    if accepted:
        implementation.verify_published_ports(published(actual), expected)
    else:
        with pytest.raises(VaultRewindError) as error:
            implementation.verify_published_ports(published(actual), expected)
        assert error.value.code == 'PUBLIC_PORTS_UNAVAILABLE'


def test_implicit_dual_stack_allocation_does_not_authorize_explicit_ipv4_policy_expansion():
    actual = binding('0.0.0.0')
    actual['80/tcp'].append({'HostIp': '::', 'HostPort': '18103'})
    implementation.verify_published_ports(published(actual), binding(''))
    with pytest.raises(VaultRewindError):
        implementation.verify_published_ports(published(actual), binding('0.0.0.0'))


@pytest.mark.parametrize('internal,mode,accepted', [(True, 'nat', False), (False, 'routed', False), (False, 'isolated', False), (False, 'nat', True)])
def test_public_network_requires_noninternal_nat_bridge(internal, mode, accepted):
    class Networks:
        def network(self, name):
            return {'Driver': 'bridge', 'Internal': internal, 'Options': {'com.docker.network.bridge.gateway_mode_ipv4': mode}}
    if accepted:
        implementation.validate_public_network(Networks(), 'approved', binding())
    else:
        with pytest.raises(VaultRewindError) as error:
            implementation.validate_public_network(Networks(), 'approved', binding())
        assert error.value.code == 'PUBLIC_NETWORK_UNPUBLISHABLE'
    # No-public-port verification runners still support internal bridge profiles.
    implementation.validate_public_network(Networks(), 'approved', {})


@pytest.mark.parametrize('status,accepted', [(200, True), (302, False), (503, False)])
def test_public_http_uses_fixed_alive_path_and_never_follows_redirect(monkeypatch, status, accepted):
    docker = Docker()
    calls = []
    monkeypatch.setattr(docker, 'inspect', lambda _: published(binding('::')))
    class Connection:
        def __init__(self, host, port, timeout):
            calls.append((host, port))
        def request(self, method, path, headers):
            calls.append((method, path))
        def getresponse(self):
            return type('Response', (), {'status': status})()
        def close(self):
            pass
    monkeypatch.setattr(implementation.http.client, 'HTTPConnection', Connection)
    if accepted:
        assert docker.public_health('synthetic', binding('::'), 0)['public_endpoint_verified']
    else:
        with pytest.raises(VaultRewindError) as error:
            docker.public_health('synthetic', binding('::'), 0)
        assert error.value.code == 'PUBLIC_ENDPOINT_UNAVAILABLE'
    assert calls == [('::1', 18103), ('GET', '/alive')]

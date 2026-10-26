"""A failed isolated application must retire its private data before releasing its runner."""
import pytest

from tests.unit.test_core import canonical_fixture
from tests.unit.test_server import env, seed  # noqa: F401
from vaultrewind.core.errors import VaultRewindError
from vaultrewind.server.adapters import Adapters


@pytest.mark.parametrize("cleanup_fails", [False, True])
def test_candidate_validation_failure_always_attempts_verified_disposal(env, tmp_path, monkeypatch, cleanup_fails):  # noqa: F811
    settings, _engine, factory, store, _app = env
    with factory.begin() as db:
        _user, _host, runner, _policy, _repo = seed(db, store)
        runner.is_runner = True
        runner_id = runner.id
    root, _manifest = canonical_fixture(tmp_path)
    class Remote:
        def __init__(self):
            self.state = {"exists": False}
            self.calls = []
        async def upload_restore(self, *_args):
            self.state = {"exists": True, "phase": "staged"}
        async def request(self, verb, _rid, _op, _fence, payload=None):
            self.calls.append((verb, payload))
            if verb == "status":
                return self.state
            if verb == "preflight":
                return {"empty_target": True, "recovery_verified": True, "fingerprint": "a" * 64}
            if verb == "commit_restore" and payload["phase"] == "prepare_safety":
                return {"empty_target": True}
            if verb == "commit_restore":
                self.state = {"exists": True, "phase": "rolled_back"}
                raise VaultRewindError("APPLICATION_NOT_READY", "Synthetic candidate failed readiness.")
            if verb == "cleanup":
                assert payload == {"kind": "discard_candidate"}
                if cleanup_fails:
                    raise VaultRewindError("CANDIDATE_CLEANUP_INCOMPLETE", "Synthetic cleanup outage.", True)
                return {"candidate_cleanup_outcome": "complete", "staging_cleaned": True}
            raise AssertionError(f"Unexpected remote operation: {verb}")
    remote = Remote()
    adapters = Adapters(settings, factory)
    monkeypatch.setattr(adapters, "remote", lambda *_args: (remote, runner_id))
    with pytest.raises(VaultRewindError) as error:
        adapters.test_application(runner_id, root, "synthetic-operation", 1)
    assert any(v == "cleanup" for v, _ in remote.calls)
    if cleanup_fails:
        assert error.value.code == "RUNNER_CLEANUP_FAILED" and error.value.retryable
        assert error.value.details["cleanup_result"] == "incomplete"
    else:
        assert error.value.code == "APPLICATION_NOT_READY"
        assert error.value.details["cleanup_result"] == "complete"

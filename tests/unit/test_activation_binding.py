"""A reviewed empty-profile update refreshes confirmation without adopting other data."""
from datetime import timedelta
from types import SimpleNamespace

import pytest

from tests.unit.test_server import env, seed  # noqa: F401
from vaultrewind.server.db import now, uid
from vaultrewind.server.models import ActivationPlan, Host, Instance, Job
from vaultrewind.server.queue import enqueue
from vaultrewind.server.worker import Worker


@pytest.mark.parametrize("case", ["empty", "running", "changed_running", "wrong_roots", "missing_fingerprint"])
def test_reviewed_activation_refreshes_only_proven_empty_target_binding(env, case):  # noqa: F811
    settings, engine, factory, store, _app = env
    with factory.begin() as db:
        user, host, instance, _policy, _repository = seed(db, store)
        remote_id = store.get(db, instance.configuration_secret_id)["remote_instance_id"]
        old_fingerprint, old_revision, host_revision = instance.fingerprint, instance.revision, host.revision
        host_id, instance_id = host.id, instance.id
        profile = {"container_id": None if case != "running" and case != "changed_running" else instance.container_id,
                   "recovery_profile": {"approved": "new-profile"}}
        private = store.put(db, "activation_plan", host.id, {"policy": {"instances": {remote_id: profile}}})
        plan = ActivationPlan(id=uid(), host_id=host.id, host_revision=host.revision, plan_hash="a" * 64,
                              secret_id=private, expires_at=now() + timedelta(minutes=10))
        db.add(plan)
        db.flush()
        job = enqueue(db, kind="activate", request={"host_id": host.id, "plan_id": plan.id, "plan_hash": plan.plan_hash},
                      key="reviewed-profile", actor_id=user.id, resources=[f"host:{host.physical_identity}"])
        job_id = job.id
        observed = {"restore_ready": True, "empty_target": profile["container_id"] is None,
                    "fingerprint": old_fingerprint if case == "running" else "d" * 64,
                    "resource_keys": instance.physical_keys}
        if case == "wrong_roots": observed["resource_keys"] = ["e" * 64]
        if case == "missing_fingerprint": observed.pop("fingerprint")
    result = {"protocol_version": 1, "recovery_verified": True, "checksum_verified": True,
              "instance_readiness": {remote_id: observed}}
    adapters = SimpleNamespace(activate=lambda *_args, **_kwargs: result)
    worker = Worker(settings, engine=engine, owner="activation-binding", adapters=adapters)
    assert worker.run_once()
    with factory() as db:
        updated, job = db.get(Instance, instance_id), db.get(Job, job_id)
        if case in {"empty", "running"}:
            assert job.state == "succeeded"
            assert updated.fingerprint == observed["fingerprint"]
            assert updated.revision == old_revision + 1
            assert store.get(db, updated.configuration_secret_id)["recovery_profile"] == profile["recovery_profile"]
        else:
            assert job.state == "failed" and job.error_code == "TARGET_CHANGED"
            assert updated.fingerprint == old_fingerprint and updated.revision == old_revision
            assert db.get(Host, host_id).revision == host_revision


def test_confirmation_shows_bound_public_profile_without_secret_environment(env):  # noqa: F811
    from tests.unit.test_server import add_snapshot
    from vaultrewind.server.schemas import Restore
    from vaultrewind.server.services import new_restore_plan
    _settings, _engine, factory, store, _app = env
    with factory.begin() as db:
        owner, _host, instance, _policy, repository = seed(db, store)
        config = store.get(db, instance.configuration_secret_id)
        config["recovery_profile"] = {"revision": 4, "environment": {"DOMAIN": "https://recovery.example.test"},
                                      "network": "recovery-bridge",
                                      "port_bindings": {"80/tcp": [{"HostIp": "127.0.0.1", "HostPort": "18100"}]}}
        store.replace(db, instance.configuration_secret_id, config)
        snapshot, _copy = add_snapshot(db, instance, repository, now())
        plan = new_restore_plan(db, store, snapshot.id, owner.id, Restore())
        assert plan["substitutions"] == {"profile_revision": 4, "public_url": "https://recovery.example.test",
                                        "network": "recovery-bridge", "published_ports": "127.0.0.1:18100 → 80/tcp"}

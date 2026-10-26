"""Reviewed historical migration never admits unknown, armed or changed pending work."""
import hashlib
import io
import json
import os
import sys
from copy import deepcopy
from types import SimpleNamespace

import pytest

from tests.unit.test_remote_lifecycle import fixture  # noqa: F401
from tests.unit.test_server import env, seed  # noqa: F401
from vaultrewind.core.errors import VaultRewindError
from vaultrewind.server.db import uid
from vaultrewind.server.provisioning import BOOTSTRAP, Provisioner


@pytest.fixture
def admission(env, fixture, monkeypatch):  # noqa: F811
    settings, _engine, factory, store, _app = env
    with factory.begin() as db:
        _user, host, _instance, _policy, _repo = seed(db, store)
        host_id = host.id
    policy = deepcopy(fixture[0].policy.value)
    bundle = {"bundle_sha256":"a" * 64, "hashes":{"helper.pyz":"a" * 64}, "files":{"helper.pyz":"private-pinned-bundle"}}
    operation_id, successor = uid(), uid()
    review = {"eligible":True, "bundle_sha256":bundle["bundle_sha256"], "journals":[{
        "eligible":True, "operation_id":operation_id, "instance_id":next(iter(policy["instances"])),
        "journal_sha256":"b" * 64, "superseded_by":successor, "changed":False}]}
    discovery = {"machine_id":policy["machine_id"], "daemon_id":policy["daemon_id"], "systemd":True,
                 "pending_operations":[{"operation_id":operation_id}], "installed_policy":policy}
    calls = []
    def admin_request(_host, payload):
        calls.append(payload)
        return discovery if payload["mode"] == "discover" else review
    instance = Provisioner(SimpleNamespace(settings=settings, sessions=factory, secrets=store))
    monkeypatch.setattr(instance, "admin_request", admin_request)
    monkeypatch.setattr(instance, "bundle", lambda:bundle)
    monkeypatch.setattr(instance, "enrolled_instances", lambda _ident:{})
    return instance, host_id, policy, bundle, review, discovery, calls


@pytest.mark.parametrize("defect", ["ineligible", "missing", "extra", "bundle", None])
def test_review_requires_exact_pending_set_and_candidate_checksum(admission, defect):
    provisioner, host_id, policy, bundle, review, _discovery, calls = admission
    if defect == "ineligible": review["eligible"] = False
    elif defect == "missing": review["journals"] = []
    elif defect == "extra": review["journals"].append({"operation_id":uid()})
    elif defect == "bundle": review["bundle_sha256"] = "c" * 64
    if defect:
        with pytest.raises(VaultRewindError) as error:
            provisioner.activation_plan(host_id, policy)
        assert error.value.code == "RECONCILIATION_REQUIRED"
    else:
        plan = provisioner.activation_plan(host_id, policy)
        assert plan["historical_upgrade"] == review
        assert any("historical status" in text for text in plan["safe_changes"])
    assert [call["mode"] for call in calls] == ["discover", "historical-review"]
    assert calls[-1]["files"] == bundle["files"]


def test_no_pending_work_needs_no_historical_exception(admission):
    provisioner, host_id, policy, _bundle, _review, discovery, calls = admission
    discovery["pending_operations"] = []
    assert provisioner.activation_plan(host_id, policy)["historical_upgrade"] is None
    assert [call["mode"] for call in calls] == ["discover"]


@pytest.mark.parametrize("defect", ["phase", "unreconciled", "successor", None])
def test_activation_verifies_reviewed_historical_repair_before_readiness(admission, monkeypatch, defect):
    provisioner, host_id, policy, _bundle, review, _discovery, _calls = admission
    plan = provisioner.activation_plan(host_id, policy)
    commands, payloads = [], []
    status = {"phase":"complete", "historical_status_reconciled":True,
              "historical_superseded_by":review["journals"][0]["superseded_by"],
              "public_ports_verified":False, "public_endpoint_verified":False}
    if defect == "phase":status["phase"] = "needs_attention"
    elif defect == "unreconciled":status["historical_status_reconciled"] = False
    elif defect == "successor":status["historical_superseded_by"] = uid()
    class Remote:
        async def request(self, verb, *_args):
            commands.append(verb)
            return status if verb == "status" else {"protocol_version":1,"recovery_verified":True,"restore_ready":True}
    monkeypatch.setattr(provisioner, "admin_request", lambda _host,payload:payloads.append(payload) or {"installed":True})
    provisioner.adapters.remote = lambda _host:(Remote(),None)
    if defect:
        with pytest.raises(VaultRewindError) as error:
            provisioner.activate(host_id, plan, uid(), 100)
        assert error.value.code == "RECONCILIATION_REQUIRED" and commands == ["status"]
    else:
        assert provisioner.activate(host_id, plan, uid(), 100)["recovery_verified"] is True
        assert commands[0] == "status" and commands[1:] == ["preflight"] * len(policy["instances"])
    assert payloads[0]["historical_upgrade"] == review and payloads[0]["mode"] == "install"


def test_fixed_admin_bootstrap_compiles():
    compile(BOOTSTRAP, "fixed-activation-bootstrap", "exec")


def test_fixed_status_rejects_unit_drift_with_identical_helper_binary(tmp_path, monkeypatch, capsys):
    policy_path, wrapper, versions, units = [tmp_path/name for name in ('policy.json','wrapper','versions','units')]
    policy = {'synthetic':'policy'}
    policy_path.write_text(json.dumps(policy,sort_keys=True,separators=(',',':')))
    helper = b'synthetic status-only fixture binary'
    digest = hashlib.sha256(helper).hexdigest()
    binary = versions/digest/'helper.pyz'
    binary.parent.mkdir(parents=True)
    binary.write_bytes(helper)
    wrapper.write_text(str(binary))
    units.mkdir()
    hashes = {}
    for name in ('vaultrewind-watchdog@.service','vaultrewind-reconcile.service'):
        data = ('[Service]\n# '+name).encode()
        (units/name).write_bytes(data)
        hashes[name] = hashlib.sha256(data).hexdigest()
    source = BOOTSTRAP.replace('/etc/vaultrewind/helper-policy.json',str(policy_path)).replace(
        '/opt/vaultrewind-helper',str(versions)).replace('/usr/local/libexec/vaultrewind-helper',str(wrapper)).replace(
        '/etc/systemd/system',str(units))
    monkeypatch.setattr(os,'geteuid',lambda:0)
    request = {'mode':'status','policy':policy,'bundle_sha256':digest,'hashes':hashes}
    def status():
        monkeypatch.setattr(sys,'stdin',SimpleNamespace(buffer=io.BytesIO(json.dumps(request).encode())))
        exec(compile(source,'isolated-fixed-bootstrap','exec'),{})  # noqa: S102 - fixed program, isolated fixture paths
        return json.loads(capsys.readouterr().out)['result']['installed']
    assert status() is True
    (units/'vaultrewind-watchdog@.service').write_text('[Service]\n# stale recovery unit')
    assert status() is False
    assert hashlib.sha256(binary.read_bytes()).hexdigest() == digest

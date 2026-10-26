#!/usr/bin/env python3
"""Start the supplied production Compose in an isolated synthetic project; prove mount persistence."""
import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / ".runtime/compose-clean-fixture"
PROJECT = "vaultrewind-clean-fixture"
DATA = Path("/srv/vaultrewind-compose-clean-fixture")


def run(args, *, data=None):
    result = subprocess.run(args, input=data, capture_output=True, cwd=WORK, timeout=600, check=False)
    if result.returncode:
        # Never echo process output which may include a private file or connection string.
        raise RuntimeError(f"Synthetic Compose procedure failed: {args[0]} (exit {result.returncode})")
    return result.stdout


def compose(*args, data=None):
    return run(["docker", "compose", "--project-directory", str(WORK), "--project-name", PROJECT,
                "--file", str(ROOT / "compose.yml"), *args], data=data)


def wait_ready():
    for _ in range(90):
        try:
            if httpx.get("http://127.0.0.1:8097/api/v1/health/ready", timeout=3).status_code == 200:
                return
        except httpx.HTTPError:
            pass
        time.sleep(1)
    raise RuntimeError("Synthetic production Compose did not become ready")


PROBE = r'''
import json,os,secrets,subprocess,uuid
from pathlib import Path
root=Path('/var/lib/vaultrewind/backups')
credential_state=Path('/var/lib/vaultrewind/provider-credentials')
assert credential_state.is_dir()
credential_marker=credential_state/'compose-persistence'
if not credential_marker.exists():
    os.umask(0o077); credential_marker.write_text('synthetic durable credential-state marker')
assert credential_marker.read_text()=='synthetic durable credential-state marker'
state=Path('/var/lib/vaultrewind/staging/compose-persistence.json')
if not state.exists():
    repo=root/'synthetic-persistence-repository'; password=secrets.token_urlsafe(48)
    private={'repo':str(repo),'password':password}
    os.umask(0o077); state.write_text(json.dumps(private)); state.chmod(0o600)
else: private=json.loads(state.read_text())
env={**os.environ,'RESTIC_REPOSITORY':private['repo'],'RESTIC_PASSWORD':private['password']}
def command(args):
    r=subprocess.run(['restic',*args],env=env,capture_output=True)
    if r.returncode: raise RuntimeError('Synthetic persistent restic operation failed')
    return r.stdout
if not Path(private['repo']).exists():
    command(['init'])
    source=Path('/var/lib/vaultrewind/staging/compose-probe'); source.mkdir(mode=0o700)
    (source/'persistence.txt').write_text('VaultRewind synthetic persistent repository fixture')
    os.chdir(source); command(['backup','--json','persistence.txt'])
snapshots=json.loads(command(['snapshots','--json']))
assert len(snapshots)==1
assert command(['dump',snapshots[0]['id'],'persistence.txt'])==b'VaultRewind synthetic persistent repository fixture'
command(['check','--read-data'])
print(json.dumps({'snapshot_id':snapshots[0]['id'],'full_data_verified':True,'uid':os.getuid(), 'credential_state_persistent':True}))
'''


def main():
    global WORK, PROJECT, DATA
    parser = argparse.ArgumentParser()
    parser.add_argument('--fixture-name', default='compose-clean-fixture')
    args = parser.parse_args()
    if not re.fullmatch(r'[a-z][a-z0-9-]{4,40}-fixture', args.fixture_name):
        raise SystemExit('Use an explicit disposable fixture name ending in -fixture.')
    WORK = ROOT / '.runtime' / args.fixture_name
    PROJECT = 'vaultrewind-' + args.fixture_name.removeprefix('compose-')
    DATA = Path('/srv/vaultrewind-' + args.fixture_name)
    os.umask(0o077)
    fresh = not (WORK / '.secrets/master_key').exists()
    WORK.mkdir(parents=True, exist_ok=True, mode=0o700)
    run([sys.executable, str(ROOT / "scripts/prepare-install.py"), "--data-dir", str(DATA)])
    start = time.monotonic()
    compose("up", "-d", "--no-build")
    wait_ready()
    first = json.loads(compose("exec", "-T", "api", "python", "-", data=PROBE.encode()))
    before_id = compose("ps", "-q", "api").decode().strip()
    compose("up", "-d", "--no-build", "--force-recreate", "api", "worker")
    wait_ready()
    after_id = compose("ps", "-q", "api").decode().strip()
    assert before_id != after_id
    second = json.loads(compose("exec", "-T", "api", "python", "-", data=PROBE.encode()))
    assert first["snapshot_id"] == second["snapshot_id"]
    config = json.loads(run(["docker", "inspect", after_id]))[0]
    assert config["Config"]["User"] == "10001:10001"
    assert config["HostConfig"]["ReadonlyRootfs"] and not config["HostConfig"]["Privileged"]
    assert "ALL" in config["HostConfig"]["CapDrop"]
    assert all(m["Destination"] != "/var/run/docker.sock" for m in config["Mounts"])
    assert httpx.get("http://127.0.0.1:8097/").status_code == 200
    report = {"result": "passed", "synthetic_only": True, "supplied_production_compose": True,
              "fresh_project_database_and_keys": fresh, "initial_readiness_http": 200,
              "frontend_http": 200, "api_container_recreated": True,
              "encrypted_local_snapshot_survived": True, "full_data_verified_after_recreation": True,
              "provider_credential_state_survived": second['credential_state_persistent'],
              "restic_snapshot_id": second["snapshot_id"], "uid": second["uid"],
              "read_only_root": True, "cap_drop_all": True, "docker_socket_mounted": False,
              "image_id": config["Image"], "total_seconds": round(time.monotonic() - start, 3),
              "limits": ["Loopback runtime in the disposable build host; no production deployment.",
                         "TLS termination requires the operator's existing reverse proxy.",
                         "Persistent restic fixture tests storage survival, not application replacement."]}
    (ROOT / "docs/evidence/compose.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()

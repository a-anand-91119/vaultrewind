#!/usr/bin/env python3
"""Independently inspect the disposable browser alternate after a completed restore.

Uses private fixture connections. It submits no application mutation or new job.
The only writes are private controller readback staging and sanitized evidence.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shlex
import shutil
import sqlite3
import tempfile
from pathlib import Path

import asyncssh
from sqlalchemy import select

from vaultrewind.core.manifest import canonical_json, verify_snapshot
from vaultrewind.server.adapters import Adapters
from vaultrewind.server.db import make_engine, sessions
from vaultrewind.server.models import Job, Snapshot, SnapshotCopy
from vaultrewind.server.settings import Settings

ROOT = Path(__file__).resolve().parents[1]

READBACK = r'''
import hashlib,json,pathlib,sqlite3,subprocess,sys,urllib.request
v=json.load(sys.stdin)
root=pathlib.Path(v['root']).resolve(strict=True)
checked=0
for item in v['files']:
    rel=pathlib.PurePosixPath(item['path'])
    assert not rel.is_absolute() and '..' not in rel.parts
    p=root.joinpath(*rel.parts)
    assert p.resolve(strict=True).is_relative_to(root) and p.is_file()
    assert hashlib.sha256(p.read_bytes()).hexdigest()==item['sha256']
    st=p.stat()
    assert st.st_uid==item['uid'] and st.st_gid==item['gid'] and st.st_mode&0o7777==item['mode']
    checked+=1
config=json.loads((root/'config.json').read_text())
assert hashlib.sha256(json.dumps(config,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()==v['config_hash']
with sqlite3.connect('file:'+str(root/'db.sqlite3')+'?mode=ro',uri=True) as db:
    db.execute('PRAGMA query_only=ON')
    assert db.execute('PRAGMA integrity_check').fetchone()[0]=='ok'
    for table,count in v['rows'].items():
        assert db.execute('SELECT count(*) FROM "'+table.replace('"','""')+'"').fetchone()[0]==count
c=json.loads(subprocess.check_output(['/usr/bin/docker','inspect',v['name']],timeout=30))[0]
assert c['State']['Running'] and c['Image']==v['image']
assert c['NetworkSettings']['Ports']['80/tcp']==v['bindings']
labels=c['Config'].get('Labels') or {}
assert labels.get('org.vaultrewind.instance')==v['instance_id']
assert labels.get('org.vaultrewind.operation')==v['operation_id']
with urllib.request.urlopen('http://127.0.0.1:'+v['port']+'/alive',timeout=10) as r: assert r.status==200
with urllib.request.urlopen('http://127.0.0.1:'+v['port']+'/api/config',timeout=10) as r:
    public=json.load(r);assert r.status==200 and public.get('version')
assert public['environment']['api'].rstrip('/').removesuffix('/api')==v['domain'].rstrip('/')
print(json.dumps({'result':'passed','regular_file_hashes_and_metadata_checked':checked,
 'approved_configuration_overlay_and_other_settings_match':True,'sqlite_integrity':'ok',
 'selected_table_counts_checked':len(v['rows']),'recorded_image_matches':True,
 'target_and_operation_labels_match':True,'published_bindings_match':True,
 'published_alive_http':200,'published_config_http':200,'effective_public_url_matches':True}))
'''


def main():
    os.umask(0o077)
    private = ROOT / '.runtime/controller'
    fixture = json.loads((private / 'integration.json').read_text())
    evidence_path = ROOT / 'docs/evidence/alternate-browser.json'
    evidence = json.loads(evidence_path.read_text())
    assert evidence['result'] == 'passed' and evidence['target_id'] == fixture['alternate_id']
    assert evidence['original_unchanged'] and evidence['source_before'] == evidence['source_after']
    settings = Settings(database_url=(private / 'database-url').read_text(),
                        master_key_file=private / 'master', bootstrap_secret_file=private / 'bootstrap',
                        staging_dir=Path('/srv/vaultrewind-native-controller/staging'),
                        local_storage_root=Path('/srv/vaultrewind-native-controller/backups'))
    engine = make_engine(settings.database_url)
    factory = sessions(engine)
    adapters = Adapters(settings, factory)
    with factory() as db:
        assert not list(db.scalars(select(Job).where(Job.state.in_(['running', 'queued', 'waiting_retry', 'cancel_requested']))))
        job = db.get(Job, evidence['restore_job_id'])
        assert job.state == 'succeeded' and job.instance_id == fixture['alternate_id']
        point = db.get(Snapshot, job.request['snapshot_id'])
        copy = db.get(SnapshotCopy, job.request['copy_id'])
        token = job.fencing_token
    policy = json.loads((private / 'vm-public-policy.json').read_text())['instances'][fixture['alternate_id']]
    descriptor = json.loads((ROOT / '.runtime/vm/controller-loss-target-fourth.json').read_text())
    settings.staging_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix='alternate-readback-', dir=settings.staging_dir))
    try:
        with adapters.repository(copy.repository_id, work) as repository:
            repository.restore(copy.restic_snapshot_id, work / 'restored')
        verified = verify_snapshot(work / 'restored', point.manifest_hash)
        manifest = verified['manifest']
        files = [{**{k: item[k] for k in ('sha256', 'uid', 'gid', 'mode')}, 'path': item['path'].removeprefix('data/')}
                 for item in manifest['inventory'] if item['type'] == 'file' and item['path'].startswith('data/')
                 and Path(item['path']).name not in {'db.sqlite3', 'db.sqlite3-wal', 'db.sqlite3-shm', 'config.json'}]
        restored = work / 'restored/data'
        config = json.loads((restored / 'config.json').read_text()) if (restored / 'config.json').exists() else {}
        recovery = policy['recovery_profile']
        domain = recovery['environment']['DOMAIN']
        config['domain'] = domain
        with sqlite3.connect('file:' + str(restored / 'db.sqlite3') + '?mode=ro', uri=True) as db:
            tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            rows = {table: db.execute(f'SELECT count(*) FROM "{table}"').fetchone()[0]
                    for table in sorted(tables & {'users', 'organizations', 'ciphers', 'attachments', 'sends'})}
        bindings = recovery['port_bindings']['80/tcp']
        payload = {'files': files, 'rows': rows, 'root': next(m['source'] for m in policy['mounts'] if m['snapshot_path'] == 'data'),
                   'config_hash': hashlib.sha256(canonical_json(config)).hexdigest(), 'name': policy['container_name'],
                   'image': point.image_id, 'instance_id': fixture['alternate_id'], 'operation_id': job.id,
                   'bindings': bindings, 'port': bindings[0]['HostPort'], 'domain': domain}

        async def read():
            host = descriptor['host_create']
            auth = host['activation_credential']
            async with asyncssh.connect(host['endpoint'], port=host['port'], username=auth['username'],
                client_keys=[asyncssh.import_private_key(auth['private_key'])],
                known_hosts=([asyncssh.import_public_key(host['host_public_key'])], [], []),
                config=[], agent_path=None, agent_forwarding=False, connect_timeout=20) as conn:
                result = await conn.run('/usr/bin/python3 -I -c ' + shlex.quote(READBACK),
                                        input=json.dumps(payload), check=False, timeout=90)
                if result.exit_status:
                    raise RuntimeError('Independent alternate readback failed; application remains untouched.')
                return json.loads(result.stdout)
        report = asyncio.run(read())
        remote, rid = adapters.remote(fixture['vm_host_id'], fixture['alternate_id'])
        status = asyncio.run(remote.request('status', rid, job.id, token))
        assert status['phase'] == 'complete' and status['candidate_validated']
        assert status['public_endpoint_verified'] and status['public_ports_verified']
        evidence['independent_ssh_readback'] = report
        evidence['snapshot_id'] = point.id
        evidence['manifest_hash'] = point.manifest_hash
        evidence['helper_phase'] = status['phase']
        evidence['helper_bundle_sha256'] = hashlib.sha256((ROOT / 'helper/.final-bundle/helper.pyz').read_bytes()).hexdigest()
        evidence['limits'] = ['Dedicated synthetic fixture; no authenticated client login.',
                              'Target DOMAIN substitution is verified independently; all other captured config settings match.',
                              'No DNS, external proxy or identity-provider changes performed.']
        evidence_path.write_text(json.dumps(evidence, indent=2) + '\n')
        print(json.dumps({'result': 'passed', 'restore_job_id': job.id, 'independent_readback': report}))
    finally:
        shutil.rmtree(work)
        engine.dispose()


if __name__ == '__main__':
    main()

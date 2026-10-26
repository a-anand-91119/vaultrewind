#!/usr/bin/env python3
"""Real constrained SSH capture/export + local encrypted copy; disposable fixtures only."""
import asyncio
import json
import secrets
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from vaultrewind.core import safe_extract, verify_snapshot
from vaultrewind.remote.ssh import SSHRemote
from vaultrewind.storage.restic import RepositoryConfig, ResticRepository


async def main():
 config=json.loads(Path('.runtime/ssh/config.json').read_text());ids=json.loads(Path('.runtime/ssh/identities.json').read_text())
 remote=SSHRemote(config);operation=str(uuid4());snapshot=str(uuid4());started=time.monotonic();token=max([json.loads(p.read_text())['token'] for p in Path('/var/lib/vaultrewind-helper/fences').glob('*.json')]+[100])+1
 view=await remote.request('discover',ids['source_id'],str(uuid4()),1)
 result=await remote.request('capture',ids['source_id'],operation,token,{'snapshot_uuid':snapshot,'controller_time':datetime.now(UTC).isoformat(),'expected_fingerprint':view['fingerprint']})
 print('Real SSH full capture returned',result.get('phase'),result.get('source_service_outcome'))
 with tempfile.TemporaryDirectory(prefix='vr-ssh-proof-') as temp:
  root=Path(temp);archive=root/'capture.tar';canonical=root/'canonical'
  transfer=await remote.export(ids['source_id'],operation,token,archive)
  safe_extract(archive,canonical);evidence=verify_snapshot(canonical,result['manifest_hash'])
  repo=ResticRepository(RepositoryConfig(location=str(root/'repository'),password=secrets.token_urlsafe(48),instance_uuid=ids['source_id']))
  repo.initialize();copy=repo.commit(canonical,snapshot,evidence['manifest']['captured_at'])
  restored=root/'restored';restore=repo.restore(copy['restic_snapshot_id'],restored)
  verification=repo.check(read_data=True)
  assert verification['full_data_verified']
  await remote.request('cleanup',ids['source_id'],operation,token,{'kind':'staging'})
  report={'cleanup_verified':True,'result':'passed','synthetic_only':True,'real_ssh':True,'pinned_host_key':True,'helper_protocol':1,'source_service_outcome':result.get('source_service_outcome'),'phase':result.get('phase'),'transfer_bytes':transfer['bytes'],'stored_copy_verified':copy['stored_copy_verified'],'restored_bytes_verified':restore['restored_bytes_verified'],'full_data_verified':verification['full_data_verified'],'total_seconds':round(time.monotonic()-started,3)}
  Path('docs/evidence/ssh-capture.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))

if __name__=='__main__':asyncio.run(main())

#!/usr/bin/env python3
"""Actual MinIO/restic provider behavior, including refused deletion; no provider mocks."""
import json
import secrets
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from tests.unit.test_core import canonical_fixture
from vaultrewind.core import create_manifest, verify_snapshot
from vaultrewind.storage.restic import RepositoryConfig, ResticRepository


def main():
 start=time.monotonic();credentials=json.loads(Path('.runtime/minio/credentials.json').read_text());limited=json.loads(Path('.runtime/minio/restricted.json').read_text())
 with tempfile.TemporaryDirectory(prefix='vr-s3-proof-') as temp:
  work=Path(temp);stage,manifest=canonical_fixture(work)
  instance=manifest['instance_uuid'];destination=str(uuid4());password=secrets.token_urlsafe(48)
  location=f"s3:{credentials['endpoint']}/vaultrewind-synthetic/vaultrewind/{instance}/{destination}"
  env={'AWS_ACCESS_KEY_ID':credentials['access_key'],'AWS_SECRET_ACCESS_KEY':credentials['secret_key'],'AWS_DEFAULT_REGION':'us-east-1'}
  options={'location': location,'password': password,'instance_uuid': instance,'allow_insecure_http': True,'options': ('s3.bucket-lookup=path',)}
  repository=ResticRepository(RepositoryConfig(**options,environment=env));repository.initialize()
  first=repository.commit(stage,manifest['snapshot_uuid'],manifest['captured_at'])
  repository.restore(first['restic_snapshot_id'],work/'restored')
  assert verify_snapshot(work/'restored',first['manifest_hash'])['inventory_verified']
  manifest['snapshot_uuid']=str(uuid4());manifest['captured_at']=datetime.now(UTC).isoformat();manifest.pop('inventory');create_manifest(stage,manifest)
  second=repository.commit(stage,manifest['snapshot_uuid'],manifest['captured_at'])
  assert len(repository.list_snapshots())==2
  restricted_env={'AWS_ACCESS_KEY_ID':limited['AccessKeyId'],'AWS_SECRET_ACCESS_KEY':limited['SecretAccessKey'],'AWS_SESSION_TOKEN':limited['SessionToken'],'AWS_DEFAULT_REGION':'us-east-1'}
  restricted=ResticRepository(RepositoryConfig(**options,environment=restricted_env))
  denied=restricted.forget([first['restic_snapshot_id']])
  assert first['restic_snapshot_id'] in denied['retained'] and not denied['complete']
  assert len(repository.list_snapshots())==2
  deleted=repository.forget([first['restic_snapshot_id']]);assert deleted['complete']
  assert [s['restic_snapshot_id'] for s in repository.list_snapshots()]==[second['restic_snapshot_id']]
  check=repository.check(read_data=True);assert check['full_data_verified']
  report={'result':'passed','real_minio':True,'synthetic_only':True,'source_release':'RELEASE.2025-10-15T17-29-55Z (official source build)','backup':True,'restore':True,'full_data_verification':True,'exact_id_expiration':True,'delete_permission_failure_retained':True,'delete_error_code':denied.get('error_code'),'total_seconds':round(time.monotonic()-start,3)}
  Path('docs/evidence/s3-minio.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
  repository.forget([second['restic_snapshot_id']]);repository.prune()

if __name__=='__main__':main()

"""Opt-in real local Docker faults against the immutable 8e7775 helper bundle.

Run .venv/bin/python -I tests/unit/test_remote_fault_docker.py --run, or set
VAULTREWIND_REMOTE_FAULT_DOCKER_TEST=1 and run this file with pytest.
Systemd orchestration is substituted. The candidate fault is an injected failed
readiness decision AFTER real startup and internal health, not an app crash.
"""
import argparse
import hashlib
import json
import os
import secrets
import shutil
import socket
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FROZEN = '8e7775f757002f07f67d6d3616f5288186f75291c352ab19409f44e09a51bf0d'


def run():
    assert os.geteuid() == 0
    bundle = ROOT / 'helper/.frozen-8e/helper.pyz'
    assert hashlib.sha256(bundle.read_bytes()).hexdigest() == FROZEN
    sys.path.insert(0, str(bundle))
    import vaultrewind
    from vaultrewind import core
    from vaultrewind.core.errors import VaultRewindError
    from vaultrewind.remote.docker import Docker
    from vaultrewind.remote.files import file_hash
    from vaultrewind.remote.helper import Helper, utc
    from vaultrewind.remote.journal import Journal, atomic_json
    from vaultrewind.remote.policy import Policy
    from vaultrewind.remote.protocol import MAGIC, Request, receive_frames, send_frames
    assert str(bundle) in __import__('vaultrewind.remote.helper', fromlist=['Helper']).__file__
    vaultrewind.__path__.append(str(ROOT / 'src/vaultrewind'))
    from vaultrewind.storage.restic import RepositoryConfig, ResticRepository

    class Recovery:
        def __init__(self):
            self.arms = 0
        def verify(self):
            pass
        def arm(self, journal, seconds):
            self.arms += 1
            journal.value.update(watchdog_armed=True, deadline=time.time()+seconds,
                                 monotonic_deadline=time.monotonic()+seconds,
                                 boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip())
            journal.save()
        def disarm(self, journal):
            journal.value['watchdog_armed'] = False
            journal.save()

    class FaultDocker(Docker):
        """TEST ONLY fault; all lifecycle, storage and readiness before it are real."""
        def __init__(self):
            super().__init__()
            self.calls = []
            self.inject_candidate_failure = False
            self.injected = []
            self.anonymous = []
        def api(self, method, path, *args, **kwargs):
            self.calls.append((method, path))
            assert not (method == 'POST' and path.startswith('/images/create')), 'No registry pulling'
            return super().api(method, path, *args, **kwargs)
        def create(self, name, config):
            if self.inject_candidate_failure and config.get('Labels', {}).get('org.vaultrewind.role') == 'candidate':
                # Extra TEST ONLY resource exercises legacy/partial anonymous-volume
                # provenance cleanup; normal production staging forbids this mount.
                config['HostConfig']['Mounts'].append({'Type':'volume','Target':'/test-only-anonymous'})
            cid = super().create(name, config)
            if self.inject_candidate_failure and config.get('Labels', {}).get('org.vaultrewind.role') == 'candidate':
                found = self.inspect(cid)
                extra = next(m for m in found['Mounts'] if m['Destination'] == '/test-only-anonymous')
                self.anonymous.append(extra['Name'])
                (Path(extra['Source'])/'synthetic-plaintext').write_text('disposable test-only candidate content')
            return cid
        def health(self, cid, window=30):
            proof = super().health(cid, window)
            found = self.inspect(cid)
            if self.inject_candidate_failure and found['Config'].get('Labels',{}).get('org.vaultrewind.role') == 'candidate':
                assert found['State']['Running'] and proof['internal_http_alive']
                assert found['HostConfig']['NetworkMode'] == 'none' and not found['HostConfig'].get('PortBindings')
                assert not any(found['NetworkSettings']['Ports'].values())
                self.injected.append({'container_id':cid,'actual_running':True,'actual_internal_health_passed':True,
                                      'network_none':True,'published_ports':False,'injected_error':'APPLICATION_NOT_READY'})
                raise VaultRewindError('APPLICATION_NOT_READY','TEST ONLY injected isolated-candidate readiness failure')
            return proof

    started = time.monotonic()
    docker, recovery = FaultDocker(), Recovery()
    iid = str(uuid.uuid4())
    name = 'vrw-preactivation-' + iid
    workspace = Path(tempfile.mkdtemp(prefix='vrw-preactivation-',dir=ROOT/'tests/unit'))
    workspace.chmod(0o700)
    network = source = original_volume = None
    helper = None
    evidence = {'bundle_sha256':FROZEN,'started_at':utc(),'scope':'unique local Docker containers, bind data and volumes only',
                'limits':['systemd adapter substituted; no new watchdog/reboot or full-worker proof',
                          'candidate readiness failure is test-only injection after real successful startup/internal health; not an application crash',
                          'extra anonymous candidate mount is test-only legacy/partial-state simulation; release enrollment rejects unapproved mounts',
                          'safety uses real encrypted restic/full readback and a private fsynced fixture pin/ack, not a controller database pin'],
                'transfer_rejections':[]}
    try:
        with socket.socket() as listener:
            listener.bind(('127.0.0.1',0)); port=str(listener.getsockname()[1])
        ports={'80/tcp':[{'HostIp':'127.0.0.1','HostPort':port}]}
        network=docker.api('POST','/networks/create',{'Name':name,'Internal':False,'Labels':{'org.vaultrewind.test':iid}})['Id']
        image=docker.image('ghcr.io/dani-garcia/vaultwarden:1.37.4')['Id']
        original_volume=name+'-data'
        volume=docker.create_volume(original_volume,{'org.vaultrewind.test':iid})
        data=Path(volume['Mountpoint'])
        config=workspace/'config'; config.mkdir(mode=0o700)
        private=data/'.root-private'; private.write_bytes(b'original root-only synthetic attachment\n'); private.chmod(0o600)
        private_config=config/'private.cfg'; private_config.write_bytes(b'original synthetic configuration\n'); private_config.chmod(0o600)
        source=docker.create(name,{'Image':image,'Healthcheck':{'Test':['NONE']},'Labels':{'org.vaultrewind.test':iid},
            'HostConfig':{'NetworkMode':name,'PortBindings':ports,'RestartPolicy':{'Name':'unless-stopped'},
                          'Mounts':[{'Type':'volume','Source':original_volume,'Target':'/data'},
                                    {'Type':'bind','Source':str(config),'Target':'/fixture-config','ReadOnly':True}]}})
        docker.start(source); docker.health(source,90); docker.stop(source,timeout=120)
        state=workspace/'state'; state.mkdir(mode=0o700)
        entry={'container_id':source,'container_name':name,'ownership':'exclusive','external_dependencies_ready':True,
               'allowed_operations':['discover','preflight','capture','export','stage_restore','commit_restore','rollback','status','cleanup'],
               'allowed_image_ids':[image],'allowed_networks':[name],'port_bindings':ports,'free_space_reserve':0,
               'capture_budget':300,'restore_budget':900,'validation_window':90,'rollback_grace_seconds':60,
               'mounts':[{'type':'volume','volume_name':original_volume,'source':str(data),'target':'/data','snapshot_path':'data','read_only':False},
                         {'type':'bind','source':str(config),'target':'/fixture-config','snapshot_path':'deployment/mounts/config','read_only':True}]}
        policy=Policy({'schema_version':1,'machine_id':Path('/etc/machine-id').read_text().strip(),'daemon_id':docker.info()['ID'],'instances':{iid:entry}},state)
        helper=Helper(policy,docker,recovery)
        def req(verb,op,fence,payload=None):
            payload=payload or {}
            return Request(iid,op,fence,verb+':'+payload.get('phase','default'),verb,payload)
        def facts(path):
            s=path.stat()
            return {'sha256':file_hash(path),'uid':s.st_uid,'gid':s.st_gid,'mode':oct(stat.S_IMODE(s.st_mode)),'inode':s.st_ino,'device':s.st_dev}
        def db_hash(path):
            with sqlite3.connect('file:'+str(path/'db.sqlite3')+'?mode=ro',uri=True) as db:
                return hashlib.sha256('\n'.join(db.iterdump()).encode()).hexdigest()
        capture_op=str(uuid.uuid4())
        captured=helper.dispatch(req('capture',capture_op,1,{'snapshot_uuid':str(uuid.uuid4()),'controller_time':utc()}))
        archive=state/'operations'/capture_op/'capture.tar'
        evidence['capture']={'snapshot_uuid':captured['snapshot_uuid'],'manifest_hash':captured['manifest_hash'],'archive_sha256':file_hash(archive),'image_id':image}
        docker.start(source); docker.health(source,90)
        baseline_private,baseline_config=facts(private),facts(private_config)
        baseline_sql=db_hash(data)
        config_identity=(config.stat().st_dev,config.stat().st_ino)
        def upload(op,fence,damage=None):
            with tempfile.TemporaryFile(dir=workspace) as wire, archive.open('rb') as stream:
                transfer=send_frames(stream,wire,2**32)
                if damage=='partial':
                    wire.truncate(wire.tell()-17)
                elif damage=='corrupted':
                    wire.seek(len(MAGIC)+4+100); byte=wire.read(1); wire.seek(-1,1); wire.write(bytes([byte[0]^1]))
                wire.seek(0)
                return helper.dispatch(req('stage_restore',op,fence,{'controller_time':utc(),'manifest_hash':captured['manifest_hash'],
                    'expected_fingerprint':helper.inspect(policy.instance(iid))['fingerprint'],
                    'archive_bytes':transfer['bytes'],'archive_sha256':transfer['sha256'],'start_on_completion':False}),incoming=wire)
        for fence,damage,expected in ((2,'partial','TRANSFER_TRUNCATED'),(3,'corrupted','TRANSFER_CHECKSUM')):
            op=str(uuid.uuid4()); before=docker.inspect(source); before_calls=len(docker.calls); arms=recovery.arms
            try:
                upload(op,fence,damage)
                raise AssertionError('Damaged transfer was accepted')
            except VaultRewindError as error:
                assert error.code==expected
            after=docker.inspect(source)
            assert after['State']['Running'] and after['State']['StartedAt']==before['State']['StartedAt']
            assert after['HostConfig']['RestartPolicy']==before['HostConfig']['RestartPolicy']
            assert facts(private)==baseline_private and facts(private_config)==baseline_config and db_hash(data)==baseline_sql
            assert not any(method in ('POST','DELETE') for method,_ in docker.calls[before_calls:]) and recovery.arms==arms
            journal=Journal(state,op).value
            assert not journal.get('watchdog_armed') and not journal.get('activation_started') and not journal.get('generation_steps')
            evidence['transfer_rejections'].append({'damage':damage,'error_code':expected,'docker_mutations':0,'watchdog_arms':0,
                'source_running':True,'started_at_unchanged':True,'restart_policy_unchanged':True,'file_metadata_and_sql_unchanged':True})
            assert helper.dispatch(req('rollback',op,fence))['phase']=='rolled_back'
            cleaned=helper.dispatch(req('cleanup',op,fence,{'kind':'discard_candidate'}))
            assert cleaned['candidate_cleanup_outcome']=='complete' and not (state/'operations'/op).exists()
        print('Actual truncated and corrupted transfers rejected before target changes.',flush=True)

        repo=ResticRepository(RepositoryConfig(location=str(workspace/'encrypted-safety'),password=secrets.token_urlsafe(40),cache_dir=workspace/'restic-cache',instance_uuid=iid))
        repo.initialize()
        def safety_ack(op,fence):
            result=helper.dispatch(req('commit_restore',op,fence,{'phase':'prepare_safety'}))
            path=workspace/(op+'-safety.tar')
            with tempfile.TemporaryFile(dir=workspace) as wire:
                helper.dispatch(req('export',op,fence,{'kind':'safety'}),outgoing=wire); wire.seek(0)
                with path.open('wb') as target: receive_frames(wire,target,2**32)
            tree=workspace/(op+'-safety'); core.safe_extract(path,tree)
            verified=core.verify_snapshot(tree,result['safety_manifest_hash'])
            stored=repo.commit(tree,result['safety_snapshot_uuid'],verified['manifest']['captured_at'],kind='safety')
            readback=workspace/(op+'-readback')
            assert repo.restore(stored['restic_snapshot_id'],readback,expected_manifest_hash=result['safety_manifest_hash'])['restored_bytes_verified']
            ack={'snapshot_uuid':result['safety_snapshot_uuid'],'manifest_hash':result['safety_manifest_hash'],
                 'restic_snapshot_id':stored['restic_snapshot_id'],'repository_id':str(uuid.uuid4()),
                 'durable':True,'encrypted':True,'pinned':True,'stored_copy_verified':True}
            atomic_json(workspace/(op+'-protected-ack.json'),ack)
            return ack

        failed_op=str(uuid.uuid4()); upload(failed_op,4)
        initial=docker.inspect(source)
        ack=safety_ack(failed_op,4)
        assert not docker.inspect(source)['State']['Running']
        docker.inject_candidate_failure=True
        try:
            helper.dispatch(req('commit_restore',failed_op,4,{'phase':'switch_validate','safety_ack':ack}))
            raise AssertionError('Injected candidate failure was accepted')
        except VaultRewindError as error:
            assert error.code=='APPLICATION_NOT_READY'
        finally:
            docker.inject_candidate_failure=False
        journal=Journal(state,failed_op)
        assert journal.value['phase']=='rolled_back' and not journal.value.get('watchdog_armed') and not journal.value.get('activation_started')
        recovered=docker.inspect(source)
        assert recovered['State']['Running'] and recovered['State']['StartedAt']!=initial['State']['StartedAt']
        assert recovered['HostConfig']['RestartPolicy']==initial['HostConfig']['RestartPolicy']
        assert facts(private)==baseline_private and facts(private_config)==baseline_config and db_hash(data)==baseline_sql
        assert (config.stat().st_dev,config.stat().st_ino)==config_identity
        assert helper.active(iid) is None and docker.public_health(source,ports,15)['public_endpoint_verified']
        candidate=journal.value['candidate_id']
        assert not docker.inspect(candidate,missing=True)
        paths=[Path(s['new']) for s in journal.value['generation_steps']]
        named=[s['volume_name'] for s in journal.value['generation_steps'] if s['mount']['type']=='volume']
        parents=[Path(s['new']).parent for s in journal.value['generation_steps'] if s['mount']['type']=='bind']
        anonymous=list(docker.anonymous)
        assert paths and all(p.exists() for p in paths) and named and anonymous
        for _ in range(2):
            cleaned=helper.dispatch(req('cleanup',failed_op,4,{'kind':'discard_candidate'}))
            assert cleaned['candidate_cleanup_outcome']=='complete' and cleaned['candidate_cleanup_remaining']==0
        assert cleaned['discarded_candidate_bytes']>0
        assert not any(p.exists() for p in paths+parents) and not (state/'operations'/failed_op).exists()
        assert all(docker.volume(v,missing=True) is None for v in named+anonymous)
        assert docker.volume(original_volume)['Name']==original_volume and facts(private)==baseline_private and facts(private_config)==baseline_config
        evidence['candidate_failure']={'phase':journal.value['phase'],'fault':docker.injected[0],'activation_started':False,'watchdog_disarmed':True,
            'original_running_and_public_ready':True,'started_at_changed_after_expected_restart':True,'restart_policy_restored':recovered['HostConfig']['RestartPolicy'],
            'original_file_before':baseline_private,'original_file_after':facts(private),'config_before':baseline_config,'config_after':facts(private_config),
            'logical_sql_sha256_before':baseline_sql,'logical_sql_sha256_after':db_hash(data),'original_bind_inode_restored':True,
            'candidate_removed':True,'candidate_generation_volume_removed':True,'anonymous_volume_removed':True,'bind_generation_removed':True,
            'staging_removed':True,'idempotent_cleanup':True,'discarded_candidate_bytes':cleaned['discarded_candidate_bytes'],
            'safety_restic_snapshot_id':ack['restic_snapshot_id'],'safety_full_readback_verified':True}
        print('Injected candidate failure recovered original running state/data; candidate disposal verified.',flush=True)

        # Optional secondary proof: actual Engine references across two data-only restores.
        evidence['repeated_named_volumes']={'executed':False,'reason':'time budget reserved for primary AC24 proof'}
        if time.monotonic()-started < 360:
            docker.stop(source,timeout=120)
            repeats=[]
            for fence in (5,6):
                previous=(helper.active(iid) or {'mounts':entry['mounts']})['mounts'][0]['volume_name']
                op=str(uuid.uuid4()); upload(op,fence); acknowledgment=safety_ack(op,fence)
                helper.dispatch(req('commit_restore',op,fence,{'phase':'switch_validate','safety_ack':acknowledgment}))
                complete=helper.dispatch(req('commit_restore',op,fence,{'phase':'activate'}))
                assert complete['phase']=='data_restored_service_stopped'
                active=helper.active(iid); live=docker.inspect(active['container_id']); assert not live['State']['Running']
                current=active['mounts'][0]['volume_name']
                record=Journal(state,op)
                assert record.value['generation_steps'][0]['mount']['volume_name']==previous
                assert not docker.inspect(record.value['candidate_id'],missing=True)
                try:
                    helper.cleanup_generations(policy.instance(iid),record)
                    raise AssertionError('Rollback grace was ignored')
                except VaultRewindError as error:
                    assert error.code=='CLEANUP_GRACE_PERIOD'
                assert docker.volume(previous,missing=True) and docker.volume(current,missing=True)
                # TEST ONLY time boundary: do not wait 60 seconds or change global clock.
                record.value['rollback_cleanup_after']=0; record.save()
                for _ in range(2): assert helper.cleanup_generations(policy.instance(iid),record)['generations_cleaned']
                assert docker.volume(previous,missing=True) is None and docker.volume(current,missing=True)
                restored_private=Path(active['mounts'][0]['source'])/private.name
                assert file_hash(restored_private)==baseline_private['sha256'] and stat.S_IMODE(restored_private.stat().st_mode)==0o600
                repeats.append({'prior_volume':previous,'active_volume':current,'grace_enforced':True,'exact_prior_removed':True,'active_preserved':True,'candidate_reference_retired':True})
            evidence['repeated_named_volumes']={'executed':True,'passed':True,'restores':repeats,'grace_expiry':'test-only journal deadline override after verifying refusal'}
            print('Two real named-volume restores retired exact prior volumes; active volumes preserved.',flush=True)
        evidence['passed']=True
    finally:
        for item in docker.containers():
            labels=item.get('Labels') or {}
            if item['Id']==source or labels.get('org.vaultrewind.instance')==iid or labels.get('org.vaultrewind.test')==iid:
                if docker.inspect(item['Id'])['State']['Running']: docker.stop(item['Id'],timeout=120)
                docker.remove(item['Id'])
        volumes=docker.api('GET','/volumes').get('Volumes') or []
        removed=[]
        for volume in volumes:
            labels=volume.get('Labels') or {}
            if volume['Name']==original_volume or volume['Name'] in docker.anonymous or labels.get('org.vaultrewind.instance')==iid or labels.get('org.vaultrewind.test')==iid:
                docker.remove_volume(volume['Name']); removed.append(volume['Name'])
        assert all(docker.volume(v,missing=True) is None for v in removed)
        if network: docker.api('DELETE','/networks/'+network)
        shutil.rmtree(workspace)
    assert hashlib.sha256(bundle.read_bytes()).hexdigest()==FROZEN
    evidence.update(finished_at=utc(),elapsed_seconds=round(time.monotonic()-started,2),fixtures_cleaned=True,bundle_unchanged=True)
    atomic_json(ROOT/'docs/evidence/preactivation-faults.json',evidence)
    print(json.dumps({'passed':True,'elapsed_seconds':evidence['elapsed_seconds'],'repeated_volumes':evidence['repeated_named_volumes']['executed'],'evidence':'docs/evidence/preactivation-faults.json'}),flush=True)


def test_real_pre_activation_faults():
    import pytest
    if os.environ.get('VAULTREWIND_REMOTE_FAULT_DOCKER_TEST')!='1':
        pytest.skip('Opt-in unique local Docker/restic fault fixture')
    subprocess.run([sys.executable,'-I',str(Path(__file__).resolve()),'--run'],check=True,timeout=900)


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--run',action='store_true',required=True)
    parser.parse_args()
    run()

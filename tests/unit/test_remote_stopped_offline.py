"""Standalone opt-in real local Docker/restic proof; no shared source or VM access.

Run: .venv/bin/python -I tests/unit/test_remote_stopped_offline.py --run
Loads the reviewed helper zipapp, substitutes ONLY systemd orchestration, and
uses a private fsynced controller acknowledgment instead of a worker database.
"""
import argparse
import copy
import hashlib
import io
import json
import os
import secrets
import shutil
import socket
import stat
import sys
import tarfile
import tempfile
import time
import uuid
from pathlib import Path
from urllib.parse import quote, urlencode

ROOT = Path(__file__).resolve().parents[2]


def run(bundle):
    assert os.geteuid() == 0
    started = time.monotonic()
    sys.path.insert(0, str(bundle))
    import vaultrewind
    from vaultrewind import core
    from vaultrewind.core.errors import VaultRewindError
    from vaultrewind.remote.docker import Docker
    from vaultrewind.remote.files import build_archive, file_hash
    from vaultrewind.remote.helper import Helper, utc
    from vaultrewind.remote.journal import atomic_json
    from vaultrewind.remote.policy import Policy
    from vaultrewind.remote.protocol import Request, digest, receive_frames, send_frames
    assert str(bundle) in __import__('vaultrewind.remote.helper', fromlist=['Helper']).__file__
    # Storage is intentionally the current controller adapter; helper/core come
    # from the immutable zipapp under test.
    vaultrewind.__path__.append(str(ROOT / 'src/vaultrewind'))
    from vaultrewind.storage.restic import RepositoryConfig, ResticRepository

    class AuditedDocker(Docker):
        def __init__(self):
            super().__init__()
            self.calls = []
            self.pull_attempts = 0
        def api(self, method, path, *args, **kwargs):
            self.calls.append((method, path))
            if method == 'POST' and path.split('?')[0] in ('/images/create', '/build'):
                self.pull_attempts += 1
                raise AssertionError('Registry pulls/builds forbidden in offline fixture')
            return super().api(method, path, *args, **kwargs)

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

    docker, recovery = AuditedDocker(), Recovery()
    iid, offline_iid = str(uuid.uuid4()), str(uuid.uuid4())
    name = 'vrw-stopped-offline-' + iid
    workspace = Path(tempfile.mkdtemp(prefix='vrw-stopped-offline-', dir=ROOT / 'tests/unit'))
    workspace.chmod(0o700)
    network = saved_image = seed = source = None
    helper = None
    evidence = {'started_at': utc(), 'bundle_sha256': file_hash(bundle), 'scope': 'unique local Docker fixture; no VM, primary source, helper install, daemon change or worker',
                'limits': ['systemd adapter substituted; no new watchdog/reboot claim', 'controller pin/ack is private fsynced fixture record, not worker database',
                           'registry unavailable enforced by rejecting Docker pull/build APIs; host network not disabled',
                           'foreign architecture uses a synthetic saved-image configuration; foreign binaries are not executed']}
    try:
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = str(listener.getsockname()[1])
        ports = {'80/tcp': [{'HostIp': '127.0.0.1', 'HostPort': port}]}
        network = docker.api('POST', '/networks/create', {'Name': name, 'Internal': False, 'Labels': {'org.vaultrewind.test': iid}})['Id']
        base = docker.image('ghcr.io/dani-garcia/vaultwarden:1.37.4')
        seed_data = workspace / 'seed'
        seed_data.mkdir()
        seed = docker.create(name+'-seed', {'Image': base['Id'], 'Labels': {'org.vaultrewind.test': iid},
                    'HostConfig': {'NetworkMode': 'none', 'Mounts': [{'Type': 'bind', 'Source': str(seed_data), 'Target': '/data'}]}})
        config = copy.deepcopy(base['Config'])
        config.update(Hostname='', Domainname='', Healthcheck={'Test': ['NONE']})
        config['Labels'] = {**(config.get('Labels') or {}), 'org.vaultrewind.test': iid}
        saved_image = docker.api('POST', '/commit?' + urlencode({'container': seed, 'comment': 'disposable offline proof'}), config)['Id']
        assert saved_image != base['Id']
        docker.remove(seed)
        seed = None
        data = workspace / 'data'
        data.mkdir(mode=0o700)
        source_config = data / 'config.json'
        source_config.write_text(json.dumps({'domain': 'https://source-offline.invalid', 'signups_allowed': False}))
        source_config.chmod(0o600)
        private = data / '.root-private-fixture'
        private.write_bytes(b'root-only synthetic attachment fixture\n')
        private.chmod(0o600)
        source = docker.create(name, {'Image': saved_image, 'Labels': {'org.vaultrewind.test': iid},
                      'HostConfig': {'NetworkMode': name, 'PortBindings': ports, 'RestartPolicy': {'Name': 'no'},
                                     'Mounts': [{'Type': 'bind', 'Source': str(data), 'Target': '/data'}]}})
        docker.start(source)
        docker.health(source, 90)
        state = workspace / 'state'
        state.mkdir(mode=0o700)
        entry = {'container_id': source, 'container_name': name, 'ownership': 'exclusive', 'external_dependencies_ready': True,
                 'allowed_operations': ['discover','preflight','capture','export','stage_restore','commit_restore','rollback','status','cleanup'],
                 'allowed_image_ids': [saved_image], 'allowed_networks': [name], 'port_bindings': ports,
                 'capture_budget': 300, 'restore_budget': 900, 'validation_window': 90, 'free_space_reserve': 0,
                 'mounts': [{'type':'bind','source':str(data),'target':'/data','snapshot_path':'data','read_only':False}]}
        policy = Policy({'schema_version':1, 'daemon_id':docker.info()['ID'], 'machine_id':Path('/etc/machine-id').read_text().strip(), 'instances':{iid:entry}}, state)
        helper = Helper(policy, docker, recovery)
        def req(verb, op, fence, payload=None, target=iid):
            payload = payload or {}
            return Request(target, op, fence, verb+':'+payload.get('phase','default'), verb, payload)
        def metadata(path):
            item=path.stat()
            return {'mode':oct(stat.S_IMODE(item.st_mode)), 'uid':item.st_uid, 'gid':item.st_gid, 'sha256':file_hash(path)}
        def tree_hash():
            return digest({str(p.relative_to(data)):file_hash(p) for p in sorted(data.rglob('*')) if p.is_file()})
        # Real filesystem guard: policy reserve exceeds measured free space. No disk fill.
        before_state=docker.inspect(source)['State']
        before_hash=tree_hash()
        before_calls=len(docker.calls)
        entry['free_space_reserve']=shutil.disk_usage(state).free+1024**3
        try:
            helper.preflight(policy.instance(iid), {'controller_time':utc()})
            raise AssertionError('Oversized real free-space reserve accepted')
        except VaultRewindError as error:
            assert error.code=='INSUFFICIENT_SPACE'
        entry['free_space_reserve']=0
        after_state=docker.inspect(source)['State']
        assert before_state['Running'] and after_state['Running'] and before_state['StartedAt']==after_state['StartedAt']
        assert before_hash==tree_hash() and recovery.arms==0
        assert not any(method=='POST' for method,_ in docker.calls[before_calls:])
        evidence['AC26']={'passed':True, 'method':'policy reserve greater than actual filesystem free bytes; disk not filled',
                           'data_sha256':before_hash,'state_and_started_at_unchanged':True,'docker_mutations':0,'watchdog_arms':0}
        docker.stop(source, timeout=120)
        baseline=metadata(private)
        config_baseline=metadata(source_config)
        capture_op=str(uuid.uuid4())
        start_calls=len(docker.calls)
        captured=helper.dispatch(req('capture',capture_op,1,{'snapshot_uuid':str(uuid.uuid4()),'controller_time':utc()}))
        assert captured['phase']=='captured' and captured['source_service_outcome']=='stopped'
        assert not docker.inspect(source)['State']['Running']
        assert not any(path==f'/containers/{source}/start' for _,path in docker.calls[start_calls:])
        assert metadata(private)==baseline and metadata(source_config)==config_baseline
        snap=state/'operations'/capture_op/'capture'
        assert metadata(snap/'data'/private.name)==baseline and metadata(snap/'data/config.json')==config_baseline
        original_manifest=core.verify_snapshot(snap,captured['manifest_hash'])['manifest']
        assert not any(k.startswith('com.docker.compose.') for k in docker.inspect(source)['Config'].get('Labels',{}))
        assert not (snap/'deployment/original-compose.yaml').exists()
        evidence['AC03']={'passed':True,'before':baseline,'after_capture':metadata(private),'captured':metadata(snap/'data'/private.name),'config_before':config_baseline}
        evidence['capture']={'snapshot_uuid':captured['snapshot_uuid'],'manifest_hash':captured['manifest_hash'],'archive_sha256':file_hash(snap.with_suffix('.tar')),
                             'saved_image_sha256':file_hash(snap/'images/vaultwarden.tar'),'image_id':saved_image}
        print('Stopped capture and real filesystem guard passed.',flush=True)

        def upload(archive, manifest_hash, operation, fence, target=iid):
            with tempfile.TemporaryFile(dir=workspace) as wire, archive.open('rb') as stream:
                transfer=send_frames(stream,wire,2**32)
                wire.seek(0)
                return helper.dispatch(req('stage_restore',operation,fence,{'controller_time':utc(),'manifest_hash':manifest_hash,
                    'expected_fingerprint':helper.inspect(policy.instance(target))['fingerprint'],'archive_bytes':transfer['bytes'],
                    'archive_sha256':transfer['sha256'],'start_on_completion':False},target),incoming=wire)

        # Construct a self-consistent saved-image manifest declaring the opposite architecture.
        wrong=workspace/'wrong-architecture'
        shutil.copytree(snap,wrong)
        old_tar=wrong/'images/vaultwarden.tar'
        new_tar=wrong/'images/foreign.tar'
        with tarfile.open(old_tar,'r:') as src:
            image_manifest=json.load(src.extractfile('manifest.json'))
            old_config=image_manifest[0]['Config']
            foreign_config=json.load(src.extractfile(old_config))
            foreign_arch='arm64' if foreign_config['architecture']=='amd64' else 'amd64'
            foreign_config['architecture']=foreign_arch
            config_bytes=core.canonical_json(foreign_config)
            foreign_id='sha256:'+hashlib.sha256(config_bytes).hexdigest()
            new_config=foreign_id[7:]+'.json'
            image_manifest[0]['Config']=new_config
            with tarfile.open(new_tar,'w:') as dst:
                for item in src:
                    if item.name in (old_config,'manifest.json'):
                        continue
                    dst.addfile(item,src.extractfile(item) if item.isfile() else None)
                for filename,content in ((new_config,config_bytes),('manifest.json',core.canonical_json(image_manifest))):
                    item=tarfile.TarInfo(filename); item.size=len(content); item.mode=0o600
                    dst.addfile(item,io.BytesIO(content))
        os.replace(new_tar,old_tar)
        descriptor=json.loads((wrong/'deployment/recovery.json').read_text())
        descriptor.update(image_id=foreign_id,platform='linux/'+foreign_arch,registry_digest=None)
        atomic_json(wrong/'deployment/recovery.json',descriptor)
        meta={k:v for k,v in original_manifest.items() if k!='inventory'}
        meta.update(snapshot_uuid=str(uuid.uuid4()),image_id=foreign_id,platform='linux/'+foreign_arch,registry_digest=None,
                    image_archive_hash=file_hash(old_tar),deployment_fingerprint=digest(descriptor))
        foreign_manifest=core.create_manifest(wrong,meta)
        wrong_archive=workspace/'wrong-architecture.tar'
        build_archive(wrong,wrong_archive,2**32)
        entry['allowed_image_ids'].append(foreign_id)
        docker.start(source)
        docker.health(source,90)
        running=docker.inspect(source)['State']
        before_calls=len(docker.calls); before_arms=recovery.arms
        bad_op=str(uuid.uuid4())
        try:
            upload(wrong_archive,core.manifest_hash(foreign_manifest),bad_op,2)
            raise AssertionError('Unsupported architecture accepted')
        except VaultRewindError as error:
            assert error.code=='UNSUPPORTED_ARCHITECTURE'
        still=docker.inspect(source)['State']
        assert still['Running'] and still['StartedAt']==running['StartedAt'] and recovery.arms==before_arms
        assert not any(method=='POST' for method,_ in docker.calls[before_calls:])
        evidence['wrong_architecture']={'code':'UNSUPPORTED_ARCHITECTURE','declared_platform':'linux/'+foreign_arch,
                                        'source_running_and_started_at_unchanged':True,'docker_mutations_before_rejection':0,'new_watchdog_arms':0}
        helper.dispatch(req('rollback',bad_op,2))
        docker.stop(source,timeout=120)
        (data/'after-snapshot').write_text('must survive only in old generation and safety')
        entry['recovery_profile']={'environment':{'DOMAIN':'https://target-offline.invalid'},'network':name,'port_bindings':ports}
        restore_op=str(uuid.uuid4())
        before_calls=len(docker.calls)
        assert upload(snap.with_suffix('.tar'),captured['manifest_hash'],restore_op,3)['phase']=='staged'
        safety=helper.dispatch(req('commit_restore',restore_op,3,{'phase':'prepare_safety'}))
        safety_archive=workspace/'safety-export.tar'
        with tempfile.TemporaryFile(dir=workspace) as wire:
            helper.dispatch(req('export',restore_op,3,{'kind':'safety'}),outgoing=wire)
            wire.seek(0)
            with safety_archive.open('wb') as target: receive_frames(wire,target,2**32)
        safety_tree=workspace/'safety-export'
        core.safe_extract(safety_archive,safety_tree)
        safety_verified=core.verify_snapshot(safety_tree,safety['safety_manifest_hash'])
        repository=ResticRepository(RepositoryConfig(location=str(workspace/'encrypted-safety'),password=secrets.token_urlsafe(40),cache_dir=workspace/'restic-cache',instance_uuid=iid))
        repository.initialize()
        stored=repository.commit(safety_tree,safety['safety_snapshot_uuid'],safety_verified['manifest']['captured_at'],kind='safety')
        readback=workspace/'safety-readback'
        restored=repository.restore(stored['restic_snapshot_id'],readback,expected_manifest_hash=safety['safety_manifest_hash'])
        assert restored['restored_bytes_verified'] and (readback/'data/after-snapshot').is_file()
        ack={'snapshot_uuid':safety['safety_snapshot_uuid'],'manifest_hash':safety['safety_manifest_hash'],'restic_snapshot_id':stored['restic_snapshot_id'],
             'repository_id':str(uuid.uuid4()),'durable':True,'encrypted':True,'pinned':True,'stored_copy_verified':True}
        atomic_json(workspace/'protected-safety-ack.json',ack)
        assert helper.dispatch(req('commit_restore',restore_op,3,{'phase':'switch_validate','safety_ack':ack}))['candidate_validated']['internal_http_alive']
        result=helper.dispatch(req('commit_restore',restore_op,3,{'phase':'activate'}))
        active=helper.active(iid); final=docker.inspect(active['container_id'])
        assert result['phase']=='data_restored_service_stopped' and not final['State']['Running'] and final['HostConfig']['RestartPolicy']['Name']=='no'
        assert not docker.inspect(source)['State']['Running']
        assert not any(path==f'/containers/{source}/start' for _,path in docker.calls[before_calls:])
        assert metadata(data/private.name)==baseline and not (data/'after-snapshot').exists()
        assert json.loads((data/'config.json').read_text())['domain']=='https://target-offline.invalid'
        assert metadata(snap/'data/config.json')==config_baseline
        assert (state/'managed'/iid/'docker-create.json').is_file()
        evidence['AC10']={'passed':True,'captured_source_stayed_stopped':True,'data_only_final_phase':result['phase'],
                          'original_still_stopped':True,'final_stopped':True,'final_restart_policy':final['HostConfig']['RestartPolicy']}
        evidence['AC03'].update(after_restore=metadata(data/private.name),config_snapshot_unchanged=True)
        evidence['AC06']={'passed':True,'manually_created':True,'compose_labels_present':False,'restored_from_normalized_definition':True}
        evidence['safety']={'restic_snapshot_id':stored['restic_snapshot_id'],'manifest_hash':stored['manifest_hash'],'full_readback_verified':True,'ack_fsynced':True}
        # Explicit fixture-only start AFTER stopped-restore assertions, to inspect real runtime config.
        docker.start(final['Id']); docker.health(final['Id'],90); docker.public_health(final['Id'],ports,20)
        import http.client
        conn=http.client.HTTPConnection('127.0.0.1',int(port),timeout=5)
        try:
            conn.request('GET','/api/config'); response=conn.getresponse(); assert response.status==200
            actual_config=json.loads(response.read(1024*1024))
        finally: conn.close()
        assert actual_config['environment']['vault']=='https://target-offline.invalid'
        evidence['config_overlay']={'passed':True,'real_api_config_url_matches_approved_overlay':True,'original_snapshot_config_unchanged':True}
        docker.stop(final['Id'],timeout=120)
        print('Stopped original restore, real restic safety and effective API config passed.',flush=True)

        # Remove only our containers and unique image; base/other images remain untouched.
        for container in docker.containers():
            if container['Id']==source or container.get('Labels',{}).get('org.vaultrewind.instance')==iid:
                assert not docker.inspect(container['Id'])['State']['Running']
                docker.remove(container['Id'])
        docker.api('DELETE','/images/'+quote(saved_image,safe=''))
        assert docker.api('GET','/images/'+quote(saved_image,safe='')+'/json',missing=True) is None
        empty=workspace/'offline-target'; empty.mkdir(mode=0o700)
        alternate=copy.deepcopy(entry)
        alternate.update(container_id=None,container_name=name+'-offline')
        alternate['mounts'][0]['source']=str(empty)
        alternate['recovery_profile']['environment']['DOMAIN']='https://offline-empty.invalid'
        policy.value['instances'][offline_iid]=alternate
        offline_op=str(uuid.uuid4()); loads=sum(path.startswith('/images/load') for _,path in docker.calls)
        upload(snap.with_suffix('.tar'),captured['manifest_hash'],offline_op,4,offline_iid)
        assert docker.image(saved_image)['Id']==saved_image
        helper.dispatch(req('commit_restore',offline_op,4,{'phase':'prepare_safety'},offline_iid))
        helper.dispatch(req('commit_restore',offline_op,4,{'phase':'switch_validate'},offline_iid))
        complete=helper.dispatch(req('commit_restore',offline_op,4,{'phase':'activate'},offline_iid))
        offline_final=docker.inspect(helper.active(offline_iid)['container_id'])
        assert complete['phase']=='data_restored_service_stopped' and not offline_final['State']['Running']
        assert offline_final['Image']==saved_image and metadata(empty/private.name)==baseline
        assert sum(path.startswith('/images/load') for _,path in docker.calls)>loads and docker.pull_attempts==0
        evidence['AC11']={'passed':True,'image_absent_before_restore':True,'image_restored_from_saved_archive':True,'recorded_image_id':saved_image,
                          'actual_image_id':offline_final['Image'],'pull_attempts':docker.pull_attempts,'wrong_architecture_rejected_before_downtime':True}
        evidence['passed']=True
    finally:
        # Ownership IDs only; never prune or touch another test's fixtures.
        for item in docker.containers():
            labels=item.get('Labels') or {}
            if item['Id'] in (seed,source) or labels.get('org.vaultrewind.instance') in (iid,offline_iid) or labels.get('org.vaultrewind.test')==iid:
                found=docker.inspect(item['Id'])
                if found['State']['Running']: docker.stop(item['Id'],timeout=120)
                docker.remove(item['Id'])
        if saved_image: docker.api('DELETE','/images/'+quote(saved_image,safe=''),missing=True)
        if network: docker.api('DELETE','/networks/'+network)
        shutil.rmtree(workspace)
    evidence.update(finished_at=utc(),elapsed_seconds=round(time.monotonic()-started,2),fixture_cleaned=True)
    atomic_json(ROOT/'docs/evidence/stopped-offline.json',evidence)
    print(json.dumps({'passed':True,'elapsed_seconds':evidence['elapsed_seconds'],'bundle_sha256':evidence['bundle_sha256'],'evidence':'docs/evidence/stopped-offline.json'}),flush=True)


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--run',action='store_true',required=True)
    parser.add_argument('--bundle',type=Path,default=ROOT/'helper/.final-bundle/helper.pyz')
    args=parser.parse_args()
    run(args.bundle.resolve())

#!/usr/bin/env python3
"""Parked, independent application proof of an already completed Drive restore.

Preparation uses only stdlib and performs no I/O. Execution reads existing private
fixtures and verified readback bytes; it never opens a repository or Drive client.
Only a successful execution creates the new, sanitized evidence file.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit
from uuid import UUID

PROJECT = Path(__file__).resolve().parents[1]
PRIVATE = PROJECT / '.runtime/controller'
SOURCE_ID = '46ac8eb9-1854-4fc6-924f-af14c6b7d0c2'
ALTERNATE_ID = 'b05f7958-3d3b-48d6-a8f2-8eb900533149'
DESCRIPTOR_PROFILE_ID = '02b09a69-7c5f-4695-85f5-8514364ca6f5'
RELEASE = 'ROOTGO_READBACK'
ORIGIN = 'http://127.0.0.1:8098'
ACTIVE = {'queued', 'running', 'waiting_retry', 'cancel_requested'}
TABLES = ('users', 'organizations', 'ciphers', 'attachments', 'sends')
TARGET_NAME = 'vrw-api-alternate-' + ALTERNATE_ID
TARGET_ROOT = '/srv/' + TARGET_NAME + '/data'
PUBLIC_BINDINGS = {'80/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '18100'}]}
PUBLIC_FLAGS = ('public_endpoint_verified', 'public_ports_verified')
# overlays.apply_environment only reapplies metadata when config already exists.
# Otherwise journal.atomic_json creates mode 0600 under helper.main's umask 077;
# installed sudo/systemd helper execution is root:root (no setgid restore modes).
GENERATED_CONFIG_METADATA = {'uid': 0, 'gid': 0, 'mode': 0o600}


class DrillError(Exception):
    """Contains public codes only; private exception text is never forwarded."""


def require(value, code):
    if not value:
        raise DrillError(code)


def identifier(value):
    try:
        parsed = UUID(value)
        if str(parsed) != value or parsed.version not in {1, 2, 3, 4, 5}:
            raise ValueError()
    except (ValueError, TypeError, AttributeError):
        raise argparse.ArgumentTypeError('A canonical UUID is required.') from None
    return value


def digest(value):
    # Same serialization as prove_drive_recovery's checkpoint/source witnesses.
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def require_execution(args):
    require(args.execute and args.root_go == RELEASE and args.dedicated_test_account and args.destination_id,
            'DRIVE_APPLICATION_PARKED_ROOTGO_READBACK_AND_DEDICATED_SCOPE_REQUIRED')
    identifier(args.destination_id)
    identifier(args.run_id or args.destination_id)


def no_symlinks(path):
    require(path.is_absolute() and all(not p.is_symlink() for p in (path, *path.parents)),
            'PRIVATE_PATH_SYMLINK_REJECTED')


def private_directory(path):
    no_symlinks(path)
    info = path.stat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o077,
            'EXISTING_PRIVATE_DIRECTORY_REQUIRED')


def private_read(path):
    no_symlinks(path)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o077,
                'EXISTING_PRIVATE_FILE_REQUIRED')
        return stream.read()


def validate_checkpoint(state, destination_id, run_id):
    require(state.get('version') == 1 and state.get('source_id') == SOURCE_ID and
            state.get('destination_id') == destination_id and state.get('run_id') == run_id and
            state.get('dedicated_test_account_acknowledged') is True, 'CHECKPOINT_IDENTITY_MISMATCH')
    for key in ('snapshot_id', 'drive_copy_id', 'local_copy_id'):
        identifier(state[key])
    cloud, local = state['drive_readback'], state['local_readback']
    for record, backend, copy_id in ((cloud, 'drive', state['drive_copy_id']),
                                     (local, 'local', state['local_copy_id'])):
        require(record.get('complete') is True and record.get('backend') == backend and
                record.get('snapshot_id') == state['snapshot_id'] and record.get('copy_id') == copy_id and
                record.get('restored_bytes_verified') is True and
                record.get('saved_image_inventory_verified') is True and record.get('sqlite_integrity') == 'ok',
                'COMPLETE_MATCHING_READBACKS_REQUIRED')
        identifier(record['repository_id'])
        require(re.fullmatch(r'[0-9a-f]{64}', record.get('manifest_hash', '')) and
                re.fullmatch(r'[0-9a-f]{64}', record.get('whole_file_map_sha256', '')),
                'READBACK_HASH_IDENTITY_REQUIRED')
    require(all(cloud[key] == local[key] for key in
                ('manifest_hash', 'whole_file_map_sha256', 'file_count', 'logical_bytes')),
            'LOCAL_AND_DRIVE_READBACKS_DIFFER')
    alternate = state['alternate_restore']
    job_id = identifier(alternate['job_id'])
    plan = state['restore_plan']
    require(alternate.get('complete') is True and alternate.get('target_id') == ALTERNATE_ID and
            alternate.get('selected_drive_copy_id') == state['drive_copy_id'] and
            alternate.get('source_started_at_and_whole_hash_unchanged') is True and
            alternate.get('public_alive_config_200') is True and alternate.get('application_started') is True and
            plan.get('target_id') == ALTERNATE_ID and plan.get('copy_id') == state['drive_copy_id'] and
            state['steps']['restore'].get('job_id') == job_id and
            state['steps']['restore']['job'].get('state') == 'succeeded',
            'COMPLETED_EXACT_ALTERNATE_RESTORE_REQUIRED')
    identifier(plan['id'])
    witness = state['source_before_restore']
    require(witness.get('running') is True and witness.get('container_id') and witness.get('started_at') and
            re.fullmatch(r'[0-9a-f]{64}', witness.get('whole_inventory_sha256', '')),
            'ORIGINAL_SOURCE_WITNESS_REQUIRED')
    return state


def validate_fixture(fixture, policy, descriptor):
    require(fixture.get('source_id') == SOURCE_ID and fixture.get('alternate_id') == ALTERNATE_ID,
            'EXACT_NATIVE_SYNTHETIC_FIXTURE_REQUIRED')
    identifier(fixture['vm_host_id'])
    host = descriptor['host_create']
    require(host.get('endpoint') == '127.0.0.1' and host.get('port') == 22229 and
            host['activation_credential'].get('username') == 'root' and
            host['activation_credential'].get('private_key') and host.get('host_public_key'),
            'PINNED_VM_ADMIN_DESCRIPTOR_REQUIRED')
    # This descriptor supplies the admin connection, NOT the alternate application profile.
    require(descriptor.get('remote_instance_id') == DESCRIPTOR_PROFILE_ID and
            DESCRIPTOR_PROFILE_ID in descriptor['policy']['instances'], 'DESCRIPTOR_PROFILE_IDENTITY_MISMATCH')
    target = policy['instances'][ALTERNATE_ID]
    mounts = target['mounts']
    require(target.get('container_name') == TARGET_NAME and len(mounts) == 1 and
            mounts[0] == {'type': 'bind', 'source': TARGET_ROOT, 'target': '/data',
                          'read_only': False, 'snapshot_path': 'data'}, 'EXACT_ALTERNATE_DATA_PROFILE_REQUIRED')
    recovery = target['recovery_profile']
    require(recovery.get('port_bindings') == PUBLIC_BINDINGS and target.get('port_bindings') == PUBLIC_BINDINGS,
            'EXACT_APPROVED_18100_BINDINGS_REQUIRED')
    environment = recovery['environment']
    require(isinstance(environment, dict) and set(environment) == {'DOMAIN'}, 'ONLY_DOMAIN_OVERLAY_ALLOWED')
    domain = environment['DOMAIN']
    url = urlsplit(domain)
    require(url.scheme in {'http', 'https'} and url.hostname and not url.username and not url.password and
            not url.query and not url.fragment and not any(ord(c) <= 32 for c in domain) and
            domain == domain.rstrip('/'), 'APPROVED_DOMAIN_REQUIRED')
    return target


def validate_catalog(state, destination_id, scope):
    """Pure binding check, also used on the fresh catalog read after SSH."""
    job, point, copy = scope['job'], scope['snapshot'], scope['copy']
    target, source, host = scope['target'], scope['source'], scope['host']
    require(not scope['active_jobs'], 'SOURCE_OR_TARGET_JOB_ACTIVE')
    require(source['id'] == SOURCE_ID and target['id'] == ALTERNATE_ID and
            target['host_id'] == host['id'] == scope['vm_host_id'] and source['host_id'] != target['host_id'] and
            not target['is_runner'] and not target['archived'] and not source['archived'] and
            target['readiness'] == 'ready' and host['endpoint'] == '127.0.0.1' and host['port'] == 22229,
            'EXACT_ENROLLED_ALTERNATE_REQUIRED')
    require(job['id'] == state['alternate_restore']['job_id'] == state['steps']['restore']['job_id'] and
            job['state'] == 'succeeded' and job['kind'] == 'restore' and job['instance_id'] == ALTERNATE_ID and
            job['target_activation_outcome'] == 'complete' and not job['reconcile_required'] and
            job['fencing_token'] > 0, 'SUCCEEDED_CURRENT_RESTORE_REQUIRED')
    request = job['request']
    require(request.get('snapshot_id') == state['snapshot_id'] == point['id'] and
            request.get('copy_id') == state['drive_copy_id'] == copy['id'] and
            request.get('target_id') == ALTERNATE_ID and request.get('plan_id') == state['restore_plan']['id'] and
            request.get('manifest_hash') == point['manifest_hash'], 'RESTORE_JOB_COPY_IDENTITY_MISMATCH')
    plan = scope['plan']
    require(plan['id'] == request['plan_id'] and plan['snapshot_id'] == point['id'] and
            plan['copy_id'] == copy['id'] and plan['target_id'] == ALTERNATE_ID and plan['job_id'] == job['id'] and
            plan['manifest_hash'] == point['manifest_hash'] and plan['consumed_at'] is not None,
            'CONSUMED_RESTORE_PLAN_IDENTITY_MISMATCH')
    result = job['result']
    require(all(result.get(key) is True for key in (*PUBLIC_FLAGS, 'candidate_validated',
                                                  'application_started', 'restored_bytes_verified')),
            'BOTH_API_PUBLIC_PROOF_FLAGS_REQUIRED')
    require(result.get('active_generation') == target['active_generation'] == job['id'],
            'CURRENT_TARGET_GENERATION_MISMATCH')
    require(point['instance_id'] == SOURCE_ID and point['completeness'] == 'complete' and
            re.fullmatch(r'sha256:[0-9a-f]{64}', point['image_id']), 'COMPLETE_SOURCE_SNAPSHOT_REQUIRED')
    for record, repo, destination, backend, readback in (
            (copy, scope['repository'], scope['destination'], 'drive', state['drive_readback']),
            (scope['local_copy'], scope['local_repository'], scope['local_destination'], 'local',
             state['local_readback'])):
        require(record['id'] == readback['copy_id'] and record['snapshot_id'] == point['id'] and
                record['state'] == 'complete' and record['repository_id'] == repo['id'] == readback['repository_id']
                and repo['instance_id'] == SOURCE_ID and repo['destination_id'] == destination['id'] and
                destination['backend'] == backend and not destination['archived'] and
                record['manifest_hash'] == point['manifest_hash'] == readback['manifest_hash'] and
                re.fullmatch(r'[0-9a-f]{64}', record.get('restic_snapshot_id') or ''),
                'EXACT_COMPLETE_COPY_REQUIRED')
    require(scope['destination']['id'] == destination_id and
            scope['remote_instance_id'] == ALTERNATE_ID, 'DRIVE_DESTINATION_OR_REMOTE_PROFILE_MISMATCH')


def validate_api_job(view, job):
    require(all(view.get(k) == job[k] for k in ('id', 'kind', 'state', 'instance_id', 'target_activation_outcome'))
            and all(view.get('result', {}).get(k) is True for k in PUBLIC_FLAGS) and
            view.get('result', {}).get('active_generation') == job['id'], 'API_CURRENT_PUBLIC_PROOF_MISMATCH')


def validate_helper(status, job):
    require(status.get('exists') is True and status.get('kind') == 'restore' and
            status.get('phase') == 'complete' and status.get('instance_id') == ALTERNATE_ID and
            status.get('operation_id') == job['id'] and status.get('active_generation') == job['id'] and
            status.get('fencing_token') == job['fencing_token'] and status.get('candidate_validated') and
            all(status.get(k) is True for k in PUBLIC_FLAGS), 'CURRENT_HELPER_PUBLIC_PROOF_MISMATCH')


def source_witness():
    from scripts.prove_drive_recovery import DriveDrill
    # The existing method is read-only and does not access self. Never construct
    # DriveDrill: its constructor creates clients and mutates its checkpoint.
    return DriveDrill.source_witness(None)


def readback_program():
    from scripts.prove_alternate_readback import READBACK
    # Reuse every content/application check verbatim. Extra guards bind its reads
    # to a real, nonsymlink mount and to the current container generation.
    prefix = r'''
import contextlib,io,json,pathlib,subprocess,sys
v=json.load(sys.stdin)
root=pathlib.Path(v['root'])
for rel in ['', 'config.json', 'db.sqlite3']+[x['path'] for x in v['files']]:
    p=root/rel
    assert all(not x.is_symlink() for x in [p,*p.parents])
initial=json.loads(subprocess.check_output(['/usr/bin/docker','inspect',v['name']],timeout=30))[0]
sys.stdin=io.StringIO(json.dumps(v))
out=io.StringIO()
with contextlib.redirect_stdout(out):
'''
    suffix = r'''
report=json.loads(out.getvalue())
assert c['Id']==initial['Id'] and c['State']['StartedAt']==initial['State']['StartedAt']
mounts=[m for m in c['Mounts'] if m['Destination']=='/data']
assert len(mounts)==1 and mounts[0]['Type']=='bind' and mounts[0]['Source']==v['root'] and mounts[0]['RW']
assert c['HostConfig']['PortBindings']==v['all_bindings']
st=(root/'config.json').stat()
assert all(getattr(st,'st_'+key)==v['config_metadata'][key] for key in ['uid','gid'])
assert st.st_mode&0o7777==v['config_metadata']['mode']
report.update(current_container_and_data_mount_match=True,configuration_metadata_matches=True)
print(json.dumps(report))
'''
    return prefix + '    exec(' + repr(READBACK) + ')\n' + suffix


def build_payload(restored, state, scope, profile):
    import sqlite3

    from vaultrewind.core.manifest import canonical_json, sha256_file, verify_snapshot
    from vaultrewind.remote.overlays import approved_environment
    private_directory(restored)
    for relative in ('manifest/manifest.json', 'manifest/inventory.json', 'data/db.sqlite3',
                     'data/config.json', 'images/vaultwarden.tar'):
        no_symlinks(restored / relative)
    for suffix in ('-wal', '-shm'):
        require(not (restored / ('data/db.sqlite3' + suffix)).exists() and
                not (restored / ('data/db.sqlite3' + suffix)).is_symlink(),
                'STANDALONE_NORMALIZED_DATABASE_REQUIRED')
    verified = verify_snapshot(restored, scope['snapshot']['manifest_hash'])
    manifest = verified['manifest']
    require(json.loads(private_read(restored / 'manifest/manifest.json')) == manifest and
            json.loads(private_read(restored / 'manifest/inventory.json')) == manifest['inventory'],
            'SAVED_INVENTORY_DOCUMENT_MISMATCH')
    require(manifest['snapshot_uuid'] == state['snapshot_id'] and manifest['instance_uuid'] == SOURCE_ID and
            manifest['image_id'] == scope['snapshot']['image_id'] and
            sha256_file(restored / 'images/vaultwarden.tar') == manifest['image_archive_hash'],
            'LOCAL_MANIFEST_OR_SAVED_IMAGE_IDENTITY_MISMATCH')
    files = {i['path']: i['sha256'] for i in manifest['inventory'] if i['type'] == 'file'}
    readback = state['drive_readback']
    require(digest(files) == readback['whole_file_map_sha256'] and len(files) == readback['file_count'] and
            verified['logical_bytes'] == readback['logical_bytes'], 'EXACT_READBACK_FILE_MAP_REQUIRED')
    entries = {i['path']: i for i in manifest['inventory']}
    config_path = restored / 'data/config.json'
    config_entry = entries.get('data/config.json')
    if config_entry is not None:
        require(config_entry['type'] == 'file' and config_path.is_file(), 'CAPTURED_CONFIGURATION_REQUIRED')
        config = json.loads(config_path.read_bytes())
        require(isinstance(config, dict), 'CAPTURED_CONFIGURATION_REQUIRED')
        config_metadata = {key: config_entry[key] for key in ('uid', 'gid', 'mode')}
        config_origin = 'captured'
    else:
        # A supported environment-only source has no config.json. Its absence
        # must agree with the verified inventory and actual tree, never a link.
        require(not config_path.exists() and not config_path.is_symlink(), 'CAPTURED_CONFIG_ABSENCE_MISMATCH')
        config = {}
        config_metadata = dict(GENERATED_CONFIG_METADATA)
        config_origin = 'generated_from_verified_absence'
    environment = approved_environment(profile['recovery_profile'])
    require(set(environment) == {'DOMAIN'}, 'APPROVED_DOMAIN_REQUIRED')
    config['domain'] = environment['DOMAIN']
    excluded = {'data/db.sqlite3', 'data/db.sqlite3-wal', 'data/db.sqlite3-shm', 'data/config.json'}
    persistent = [{'path': i['path'].removeprefix('data/'),
                   **{key: i[key] for key in ('sha256', 'uid', 'gid', 'mode')}}
                  for i in manifest['inventory'] if i['type'] == 'file' and
                  i['path'].startswith('data/') and i['path'] not in excluded]
    with sqlite3.connect((restored / 'data/db.sqlite3').as_uri() + '?mode=ro&immutable=1', uri=True) as db:
        db.execute('PRAGMA query_only=ON')
        require(db.execute('PRAGMA integrity_check').fetchall() == [('ok',)], 'CAPTURED_SQLITE_INTEGRITY_FAILED')
        tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        require(set(TABLES) <= tables, 'ALL_FIVE_CAPTURED_TABLES_REQUIRED')
        rows = {table: db.execute(f'SELECT count(*) FROM "{table}"').fetchone()[0] for table in TABLES}
    payload = {'files': persistent, 'rows': rows, 'root': TARGET_ROOT, 'name': TARGET_NAME,
               'config_hash': hashlib.sha256(canonical_json(config)).hexdigest(),
               'config_metadata': config_metadata,
               'image': manifest['image_id'], 'instance_id': ALTERNATE_ID, 'operation_id': scope['job']['id'],
               'all_bindings': PUBLIC_BINDINGS,
               'bindings': PUBLIC_BINDINGS['80/tcp'], 'port': '18100', 'domain': config['domain']}
    return payload, {'manifest_hash': verified['manifest_hash'], 'saved_image_inventory_verified': True,
                     'whole_file_map_sha256': digest(files), 'file_count': len(files),
                     'logical_bytes': verified['logical_bytes'], 'configuration_origin': config_origin}


def validate_report(report, payload):
    expected = {'result': 'passed', 'regular_file_hashes_and_metadata_checked': len(payload['files']),
                'approved_configuration_overlay_and_other_settings_match': True, 'sqlite_integrity': 'ok',
                'selected_table_counts_checked': 5, 'recorded_image_matches': True,
                'target_and_operation_labels_match': True, 'published_bindings_match': True,
                'published_alive_http': 200, 'published_config_http': 200, 'effective_public_url_matches': True,
                'current_container_and_data_mount_match': True, 'configuration_metadata_matches': True}
    require(report == expected, 'INDEPENDENT_SSH_READBACK_NOT_PROVEN')
    # Emit only these fixed keys/values, never an arbitrary remote response.
    return expected


class ApplicationReadback:
    def __init__(self, args):
        require_execution(args)  # Before private reads, SQL engines, imports or clients.
        self.args = args
        self.run_id = args.run_id or args.destination_id
        self.root = PROJECT / '.runtime/drive-proof' / self.run_id
        private_directory(self.root)
        private_directory(PRIVATE)
        self.checkpoint = self.root / 'checkpoint.json'
        self.checkpoint_bytes = private_read(self.checkpoint)
        self.state = validate_checkpoint(json.loads(self.checkpoint_bytes), args.destination_id, self.run_id)
        self.fixture = json.loads(private_read(PRIVATE / 'integration.json'))
        self.policy = json.loads(private_read(PRIVATE / 'vm-public-policy.json'))
        self.descriptor = json.loads(private_read(PROJECT / '.runtime/vm/controller-loss-target-fourth.json'))
        self.profile = validate_fixture(self.fixture, self.policy, self.descriptor)
        self.evidence = PROJECT / 'docs/evidence/drive-application.json'
        no_symlinks(self.evidence)
        require(not self.evidence.exists(), 'EXISTING_EVIDENCE_REQUIRES_ROOT_REVIEW')
        # No Adapters, provider credentials or repository sessions.
        from sqlalchemy import create_engine
        from sqlalchemy.engine import make_url

        from vaultrewind.server.secrets import Secrets
        url = make_url(private_read(PRIVATE / 'database-url').decode().strip())
        require(url.get_backend_name() == 'postgresql' and url.host in {None, 'localhost', '127.0.0.1'} and
                set(url.query) <= {'host', 'sslmode'} and
                url.query.get('host') in {None, 'localhost', '127.0.0.1', '/var/run/postgresql'},
                'NATIVE_PRIVATE_POSTGRES_REQUIRED')
        private_read(PRIVATE / 'master')  # Enforce parent-symlink/ownership/mode guards before Secrets reads it.
        self.secrets = Secrets(SimpleNamespace(master_key_file=PRIVATE / 'master',
                                               accept_legacy_secret_envelopes=True))
        self.engine = create_engine(url, execution_options={'isolation_level': 'REPEATABLE READ',
                                                          'postgresql_readonly': True})

    def catalog(self):
        from sqlalchemy import select
        from sqlalchemy.orm import Session

        from vaultrewind.server.models import (
            Host,
            Instance,
            Job,
            Repository,
            RestorePlan,
            Snapshot,
            SnapshotCopy,
            StorageDestination,
        )

        def fields(row, *keys):
            require(row is not None, 'EXISTING_CATALOG_RECORD_REQUIRED')
            return {key: getattr(row, key) for key in keys}

        with Session(self.engine, autoflush=False) as db:
            def secret(identity):
                # No legacy upgrade or credential rotation is performed by this reader.
                return self.secrets.get(db, identity, upgrade=False)

            state = self.state
            target, source = db.get(Instance, ALTERNATE_ID), db.get(Instance, SOURCE_ID)
            require(target is not None and source is not None, 'EXISTING_FIXTURE_INSTANCES_REQUIRED')
            host = db.get(Host, target.host_id)
            require(host is not None, 'EXISTING_FIXTURE_HOST_REQUIRED')
            private = secret(target.configuration_secret_id)
            credentials = secret(host.credential_id)
            copy_keys = ('id', 'snapshot_id', 'repository_id', 'state', 'manifest_hash', 'restic_snapshot_id')
            copy = fields(db.get(SnapshotCopy, state['drive_copy_id']), *copy_keys)
            local = fields(db.get(SnapshotCopy, state['local_copy_id']), *copy_keys)
            repository = fields(db.get(Repository, copy['repository_id']), 'id', 'instance_id', 'destination_id')
            local_repo = fields(db.get(Repository, local['repository_id']), 'id', 'instance_id', 'destination_id')
            scope = {
                'vm_host_id': self.fixture['vm_host_id'], 'remote_instance_id': private.get('remote_instance_id'),
                'active_jobs': list(db.scalars(select(Job.id).where(
                    Job.instance_id.in_([SOURCE_ID, ALTERNATE_ID]), Job.state.in_(ACTIVE)))),
                'job': fields(db.get(Job, state['alternate_restore']['job_id']), 'id', 'kind', 'state',
                              'instance_id', 'request', 'result', 'fencing_token', 'target_activation_outcome',
                              'reconcile_required'),
                'snapshot': fields(db.get(Snapshot, state['snapshot_id']), 'id', 'instance_id', 'manifest_hash',
                                   'image_id', 'completeness'),
                'copy': copy, 'local_copy': local, 'repository': repository, 'local_repository': local_repo,
                'destination': fields(db.get(StorageDestination, repository['destination_id']),
                                      'id', 'backend', 'archived'),
                'local_destination': fields(db.get(StorageDestination, local_repo['destination_id']),
                                            'id', 'backend', 'archived'),
                'target': fields(target, 'id', 'host_id', 'container_id', 'active_generation', 'readiness',
                                 'archived', 'is_runner'),
                'source': fields(source, 'id', 'host_id', 'archived'),
                'host': fields(host, 'id', 'endpoint', 'port', 'host_public_key', 'username'),
                'plan': fields(db.get(RestorePlan, state['restore_plan']['id']), 'id', 'snapshot_id', 'copy_id',
                               'target_id', 'manifest_hash', 'job_id', 'consumed_at'),
            }
            validate_catalog(state, self.args.destination_id, scope)
            require(host.host_public_key.strip() == self.descriptor['host_create']['host_public_key'].strip(),
                    'PINNED_HOST_KEY_IDENTITY_MISMATCH')
            connection = {**credentials, **scope['host'], 'request_timeout': 90}
            return scope, connection

    def api_proof(self, job):
        import httpx
        cookies = json.loads(private_read(PRIVATE / 'api-cookies.json'))
        with httpx.Client(base_url=ORIGIN, cookies=cookies, timeout=30, trust_env=False,
                          follow_redirects=False) as client:
            response = client.get('/api/v1/jobs/' + job['id'])
            require(response.status_code == 200, 'EXISTING_API_JOB_READ_FAILED')
            validate_api_job(response.json(), job)

    async def ssh_readback(self, payload, connection, job):
        import asyncssh

        from vaultrewind.remote.ssh import SSHRemote
        host = self.descriptor['host_create']
        auth = host['activation_credential']
        # Only a constant Python program is in argv. All private values go over stdin.
        import shlex
        async with asyncssh.connect(host['endpoint'], port=host['port'], username=auth['username'],
                client_keys=[asyncssh.import_private_key(auth['private_key'], auth.get('passphrase'))],
                known_hosts=([asyncssh.import_public_key(host['host_public_key'])], [], []), config=[],
                agent_path=None, agent_forwarding=False, preferred_auth=['publickey'], password=None,
                connect_timeout=20, login_timeout=20) as conn:
            result = await conn.run('/usr/bin/python3 -I -c ' + shlex.quote(readback_program()),
                                    input=json.dumps(payload), check=False, timeout=90)
            require(result.exit_status == 0 and len(result.stdout) <= 8192, 'INDEPENDENT_SSH_READBACK_FAILED')
            report = validate_report(json.loads(result.stdout), payload)
        status = await SSHRemote(connection).request('status', ALTERNATE_ID, job['id'], job['fencing_token'])
        validate_helper(status, job)
        return report

    def execute(self):
        import asyncio
        try:
            scope, connection = self.catalog()
            self.api_proof(scope['job'])
            payload, local = build_payload(self.root / 'drive_readback-restored', self.state, scope, self.profile)
            before = source_witness()
            require(before == self.state['source_before_restore'], 'SOURCE_CHANGED_SINCE_ALTERNATE_RESTORE')
            report = asyncio.run(self.ssh_readback(payload, connection, scope['job']))
            after = source_witness()
            require(after == before, 'SOURCE_CHANGED_DURING_APPLICATION_READBACK')
            repeated, _ = self.catalog()
            require(repeated == scope, 'CATALOG_CHANGED_DURING_APPLICATION_READBACK')
            self.api_proof(repeated['job'])
            require(private_read(self.checkpoint) == self.checkpoint_bytes, 'DRIVE_CHECKPOINT_CHANGED')
            evidence = {'result': 'passed', 'synthetic_only': True, 'run_id': self.run_id,
                        'destination_id': self.args.destination_id, 'source_id': SOURCE_ID,
                        'target_id': ALTERNATE_ID, 'restore_job_id': scope['job']['id'],
                        'snapshot_id': scope['snapshot']['id'], 'drive_copy_id': scope['copy']['id'],
                        'local_readback': local, 'independent_ssh_readback': report,
                        'helper_phase': 'complete', 'helper_current_generation_and_fence_verified': True,
                        'both_api_and_helper_public_proof_flags': True, 'original_unchanged': True,
                        'original_checkpoint_source_witness_matches': True,
                        'provider_calls': 0, 'repository_sessions': 0, 'target_data_or_container_mutations': 0,
                        'user_login_tested': False, 'vaultwarden_authenticated_login_or_decryption_tested': False,
                        'limits': [('Structural content/startup proof only; no authenticated Vaultwarden login, '
                                    'decryption or client synchronization claim.'),
                                   'Only the approved target DOMAIN differs from captured configuration.',
                                   'No fresh provider read: uses the existing verified Drive readback.']}
            write_evidence(self.evidence, evidence)
            print(json.dumps({'result': 'passed', 'restore_job_id': scope['job']['id'],
                              'evidence': 'docs/evidence/drive-application.json'}), flush=True)
        finally:
            self.engine.dispose()


def write_evidence(path, evidence):
    """Exclusive creation preserves every earlier report, including a concurrent proof."""
    no_symlinks(path)
    payload = (json.dumps(evidence, indent=2) + '\n').encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink()  # Only our own exclusively-created, sanitized partial report.
        raise


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--root-go')
    parser.add_argument('--dedicated-test-account', action='store_true')
    parser.add_argument('--destination-id', type=identifier)
    parser.add_argument('--run-id', type=identifier)
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    if not args.execute:
        print(json.dumps({'status': 'prepared_not_run', 'requires': RELEASE, 'private_files_opened': 0,
                          'network_sql_provider_ssh_docker_calls': 0, 'evidence_written': False,
                          'application_readback_proven': False}), flush=True)
        return 0
    try:
        require_execution(args)
        ApplicationReadback(args).execute()
    except Exception as error:  # noqa: BLE001 - raw private exceptions must never escape.
        code = str(error) if isinstance(error, DrillError) else 'APPLICATION_READBACK_FAILED_PRIVATE_DETAILS_WITHHELD'
        if not re.fullmatch(r'[A-Z0-9_]{1,160}', code):
            code = 'APPLICATION_READBACK_FAILED_PRIVATE_DETAILS_WITHHELD'
        print(code, flush=True)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

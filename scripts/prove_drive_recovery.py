#!/usr/bin/env python3
"""Prepare by default; real dedicated-account Drive proof requires a later ROOTGO.

No HTTP client, SQL engine, credential store, subprocess or runtime directory is
created by parsing/preparation. OAuth clients and tokens come only from the
existing application's private encrypted SQL records after execution is released.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import stat
import time
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit
from uuid import UUID, uuid4

PROJECT = Path(__file__).resolve().parents[1]
ORIGIN = 'http://127.0.0.1:8098'
PRIVATE = PROJECT / '.runtime/controller'
CONTROLLER = Path('/srv/vaultrewind-native-controller')
SOURCE = Path('/srv/vaultrewind-fixtures/source/data')
SOURCE_ID = '46ac8eb9-1854-4fc6-924f-af14c6b7d0c2'
ALTERNATE_ID = 'b05f7958-3d3b-48d6-a8f2-8eb900533149'
TERMINAL = {'succeeded', 'failed', 'partial', 'cancelled', 'rolled_back', 'rollback_failed', 'needs_attention'}
ACTIVE = {'queued', 'running', 'waiting_retry', 'cancel_requested'}
POLICY_FIELDS = ('enabled', 'schedule_kind', 'timezone', 'daily_time', 'interval_hours', 'retention_days',
                 'outage_seconds', 'maintenance_seconds', 'validation_seconds', 'runner_id')


class DrillError(Exception):
    """Contains intentionally public codes only; never print raw provider errors."""


def require(value, code):
    if not value:
        raise DrillError(code)


def identifier(value):
    try:
        parsed = UUID(value)
    except (ValueError, AttributeError, TypeError):
        raise argparse.ArgumentTypeError('A canonical UUID is required.') from None
    if str(parsed) != value or parsed.version not in {1, 2, 3, 4, 5}:
        raise argparse.ArgumentTypeError('A canonical UUID is required.')
    return value


def loopback_origin(value):
    parsed = urlsplit(value)
    try:
        valid = (parsed.scheme == 'http' and parsed.hostname == '127.0.0.1' and parsed.port is not None
                 and 1024 <= parsed.port <= 65535 and not parsed.username and not parsed.password
                 and parsed.path in {'', '/'} and not parsed.query and not parsed.fragment)
    except ValueError:
        valid = False
    if not valid:
        raise argparse.ArgumentTypeError('An explicit http://127.0.0.1:<fixture-port> origin is required.')
    return value.rstrip('/')


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def validate_checkpoint(state, destination_id, run_id):
    require(isinstance(state, dict), 'CHECKPOINT_INVALID')
    if state:
        require(state.get('version') == 1 and state.get('source_id') == SOURCE_ID and
                state.get('destination_id') == destination_id and state.get('run_id') == run_id,
                'CHECKPOINT_IDENTITY_MISMATCH')
        require(isinstance(state.get('steps'), dict) and isinstance(state.get('failures'), list),
                'CHECKPOINT_INVALID')
        require(set(state['steps']) <= {'backup', 'restore', 'reconnect_probe'}, 'CHECKPOINT_UNKNOWN_JOB_STAGE')
        for record in state['steps'].values():
            require(isinstance(record, dict), 'CHECKPOINT_INVALID')
            if record.get('job_id'):
                try:
                    identifier(record['job_id'])
                except argparse.ArgumentTypeError:
                    raise DrillError('CHECKPOINT_JOB_ID_INVALID') from None
        if state.get('restore_plan'):
            require(state['restore_plan'].get('target_id') == ALTERNATE_ID,
                    'CHECKPOINT_PRIMARY_OR_UNKNOWN_TARGET_REJECTED')
    return state


def guard_credential_state(pending_count, session_count, lease_owned):
    require(pending_count == 0, 'PENDING_CREDENTIAL_ROTATION_REQUIRES_PRODUCT_RECOVERY')
    require(session_count == 0, 'REGISTERED_DRIVE_SESSIONS_REQUIRE_PRODUCT_RECOVERY')
    require(not lease_owned, 'DESTINATION_JOB_OWNS_CREDENTIAL_LEASE')


def expired_access_only(credential, now):
    require(isinstance(credential, dict) and credential.get('type') == 'google_drive_oauth' and
            credential.get('grant_id') and not credential.get('revoked') and not credential.get('revoked_at'),
            'AUTHORIZED_DEDICATED_GRANT_REQUIRED')
    token = credential.get('token')
    require(isinstance(token, dict) and token.get('access_token') and token.get('refresh_token'),
            'PRIVATE_REFRESHABLE_TOKEN_REQUIRED')
    result = copy.deepcopy(credential)
    result['token']['expiry'] = (now - timedelta(hours=1)).astimezone(UTC).isoformat().replace('+00:00', 'Z')
    return result


def submission_action(record):
    """An attempted request without an ID must be reconciled; never blindly resubmit."""
    if record.get('job_id'):
        return 'wait_existing'
    if record.get('attempted'):
        return 'lookup_existing'
    return 'submit_once'


def policy_body(original):
    body = {key: original[key] for key in POLICY_FIELDS}
    body['destinations'] = [{key: entry[key] for key in ('destination_id', 'required')}
                            for entry in original['destinations']]
    return body


def require_execution(args):
    require(args.execute and args.root_go == 'ROOTGO' and args.dedicated_test_account,
            'DRIVE_IS_PARKED_LATER_ROOTGO_AND_DEDICATED_ACCOUNT_REQUIRED')
    if args.target_id:
        require(args.target_id == ALTERNATE_ID and args.target_id != SOURCE_ID and
                args.target_go == 'ROOTGO_TARGET' and args.target_public_origin and
                urlsplit(args.target_public_origin).port not in {8098, 18180},
                'SERIALIZED_ALTERNATE_TARGET_GO_REQUIRED')
    else:
        require(not args.target_go and not args.target_public_origin, 'TARGET_ID_REQUIRED')
    if args.revoke_dedicated_grant:
        require(args.phase == 'reconnect' and args.revocation_go == 'ROOTGO_REVOKE',
                'SEPARATE_REVOCATION_SCOPE_GO_REQUIRED')
    else:
        require(not args.revocation_go, 'REVOCATION_REQUEST_REQUIRED')


def private_read(path):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o077,
                'PRIVATE_FILE_REQUIRED')
        return stream.read()


def private_write(path, value):
    from vaultrewind.security.privatefiles import atomic_private_write
    atomic_private_write(path, json.dumps(value, indent=2).encode())


class DriveDrill:
    """Runtime construction itself is behind the execution gate."""

    def __init__(self, args):
        require_execution(args)
        import httpx

        from vaultrewind.server.adapters import Adapters, SQLCredentialStore
        from vaultrewind.server.db import make_engine, sessions
        from vaultrewind.server.settings import Settings
        self.args = args
        self.destination = args.destination_id
        self.run_id = args.run_id or self.destination
        self.root = PROJECT / '.runtime/drive-proof' / self.run_id
        require(not self.root.is_symlink(), 'RUNTIME_SYMLINK_REJECTED')
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        require(not self.root.stat().st_mode & 0o077, 'PRIVATE_RUNTIME_REQUIRED')
        self.checkpoint = self.root / 'checkpoint.json'
        self.state = validate_checkpoint(json.loads(private_read(self.checkpoint)), self.destination,
                                         self.run_id) if self.checkpoint.exists() else {
            'version': 1, 'source_id': SOURCE_ID, 'destination_id': self.destination, 'run_id': self.run_id,
            'dedicated_test_account_acknowledged': True, 'steps': {}, 'failures': []}
        fixture = json.loads(private_read(PRIVATE / 'integration.json'))
        require(fixture['source_id'] == SOURCE_ID and fixture['alternate_id'] == ALTERNATE_ID,
                'EXACT_NATIVE_SYNTHETIC_FIXTURE_REQUIRED')
        self.settings = Settings(database_url=private_read(PRIVATE / 'database-url').decode().strip(),
            master_key_file=PRIVATE / 'master', bootstrap_secret_file=PRIVATE / 'bootstrap',
            staging_dir=CONTROLLER / 'staging', local_storage_root=CONTROLLER / 'backups',
            provider_credential_state_dir=args.credential_state_dir, public_origin=ORIGIN, secure_cookies=False)
        self.engine = make_engine(self.settings.database_url)
        require(self.engine.url.get_backend_name() == 'postgresql' and
                self.engine.url.host in {None, 'localhost', '127.0.0.1'}, 'NATIVE_PRIVATE_POSTGRES_REQUIRED')
        self.sessions = sessions(self.engine)
        self.adapters = Adapters(self.settings, self.sessions)
        self.store = SQLCredentialStore(self.adapters)
        self.box = self.adapters.secrets.box()
        cookies = json.loads(private_read(PRIVATE / 'api-cookies.json'))
        self.secrets_in_memory = list(cookies.values())
        self.http = httpx.Client(base_url=ORIGIN, cookies=cookies, timeout=30, trust_env=False,
            follow_redirects=False, headers={'Origin': ORIGIN, 'X-CSRF-Token': cookies['vr_csrf']})
        self.save()

    def save(self):
        private_write(self.checkpoint, self.state)

    def request(self, method, path, body=None, *, expected=200, key=None, headers=None):
        selected = dict(headers or {})
        if method != 'GET':
            selected['Idempotency-Key'] = key or str(uuid4())
        result = self.http.request(method, '/api/v1' + path, json=body, headers=selected)
        if result.status_code != expected:
            try:
                code = result.json().get('error', {}).get('code', 'HTTP_ERROR')
            except (ValueError, AttributeError):
                code = 'HTTP_ERROR'
            require(isinstance(code, str) and re.fullmatch(r'[A-Z_]{1,100}', code), 'HTTP_ERROR')
            raise DrillError(f'HTTP_{result.status_code}_{code}')
        return result.json()

    def credential(self):
        from vaultrewind.storage.credentials import credential_context
        stored = self.store.load(self.destination)
        require(stored is not None, 'AUTHORIZE_EXISTING_DESTINATION_IN_APP_FIRST')
        value = self.box.decrypt(stored.envelope, context=credential_context(self.destination))
        for key in ('client_id', 'client_secret'):
            if value.get(key):
                self.secrets_in_memory.append(value[key])
        self.secrets_in_memory.extend(str(v) for k, v in value.get('token', {}).items()
                                      if k in {'access_token', 'refresh_token'} and v)
        return stored, value

    def verify_destination(self):
        from sqlalchemy import select

        from vaultrewind.server.models import Instance, Repository, StorageDestination
        view = self.request('GET', f'/storage-destinations/{self.destination}')
        require(view['backend'] == 'drive' and view.get('credential_flags', {}).get('authorized'),
                'EXPLICIT_EXISTING_AUTHORIZED_DRIVE_DESTINATION_REQUIRED')
        stored, credential = self.credential()
        require(credential.get('type') == 'google_drive_oauth' and credential.get('scope') == 'drive.file' and
                credential.get('folder_id') == view.get('configuration', {}).get('folder_id') and
                credential.get('grant_id') and not credential.get('revoked_at') and not credential.get('revoked'),
                'AUTHORIZED_DEDICATED_MY_DRIVE_GRANT_REQUIRED')
        with self.sessions() as db:
            destination = db.get(StorageDestination, self.destination)
            source = db.get(Instance, SOURCE_ID)
            require(destination is not None and not destination.archived and source is not None and
                    not source.archived and source.readiness == 'ready', 'SOURCE_OR_DESTINATION_NOT_READY')
            foreign = list(db.scalars(select(Repository.instance_id).where(
                Repository.destination_id == self.destination, Repository.instance_id != SOURCE_ID)))
            controller = db.scalar(select(Repository.id).where(Repository.destination_id == self.destination,
                                                              Repository.instance_id.is_(None)))
            require(not foreign and not controller, 'DESTINATION_MUST_BE_DEDICATED_TO_SYNTHETIC_SOURCE')
        fingerprint = digest(view['configuration'])
        if 'configuration_sha256' in self.state:
            require(self.state['configuration_sha256'] == fingerprint, 'DRIVE_FOLDER_OR_SCOPE_CHANGED')
        else:
            self.state['configuration_sha256'] = fingerprint
            self.state['baseline_grant_sha256'] = digest(credential['grant_id'])
            self.save()
        return stored, credential

    def idle_source(self, timeout=0):
        from sqlalchemy import select

        from vaultrewind.server.models import Job
        deadline = time.monotonic() + timeout
        while True:
            with self.sessions() as db:
                active = db.scalar(select(Job.id).where(Job.instance_id == SOURCE_ID, Job.state.in_(ACTIVE)))
            if active is None:
                return
            require(time.monotonic() < deadline, 'ACTIVE_SOURCE_JOB_REQUIRES_RECONCILIATION')
            time.sleep(1)

    @contextmanager
    def credential_exclusive(self):
        """Never force expiry over pending updates, registered sessions or an owned SQL lease."""
        from sqlalchemy import select

        from vaultrewind.server.models import ResourceLease
        from vaultrewind.server.queue import ensure_resource
        from vaultrewind.storage.credentials import credential_lock
        directory = self.store.state_directory
        require(directory.is_absolute() and all(not p.is_symlink() for p in (directory, *directory.parents)),
                'CREDENTIAL_STATE_DIRECTORY_UNSAFE')
        with credential_lock(directory / 'session-locks', self.destination, timeout=1), self.sessions.begin() as db:
            for child in (directory / 'pending', directory / 'sessions'):
                if child.exists() or child.is_symlink():
                    require(not child.is_symlink() and child.is_dir() and child.stat().st_uid == os.geteuid()
                            and not child.stat().st_mode & 0o077, 'CREDENTIAL_STATE_DIRECTORY_UNSAFE')
            key = 'credential:' + self.destination
            ensure_resource(db, key)
            lease = db.scalar(select(ResourceLease).where(ResourceLease.resource_key == key).with_for_update())
            pending = list((directory / 'pending').glob(self.destination + '.*.pending-credential'))
            sessions = list((directory / 'sessions').glob(self.destination + '.*.drive-session'))
            guard_credential_state(len(pending), len(sessions), lease.owner_job_id is not None)
            yield

    def force_expiry(self):
        from vaultrewind.storage.credentials import credential_context
        if self.state.get('expiry_injection', {}).get('applied'):
            return
        with self.credential_exclusive():
            stored, current = self.credential()
            pending = self.state.get('expiry_injection')
            if pending:
                expected = self.box.decrypt(pending['expired_envelope'], context=credential_context(self.destination))
                if (stored.generation == pending['generation'] and stored.revision == pending['base_revision'] + 1
                        and current == expected):
                    pending.update(applied=True, expired_revision=stored.revision)
                    self.save()
                    return
                require(False, 'EXPIRY_CAS_RESPONSE_REQUIRES_RECONCILIATION')
            expired = expired_access_only(current, datetime.now(UTC))
            envelope = self.box.encrypt(expired, context=credential_context(self.destination))
            pending = {'base_revision': stored.revision, 'generation': stored.generation,
                'expired_envelope': envelope, 'applied': False, 'grant_sha256': digest(current['grant_id'])}
            self.state['expiry_injection'] = pending
            self.save()  # Persist planned CAS before executing it.
            revision = self.store.compare_and_swap(self.destination, envelope, stored.revision,
                                                   expected_generation=stored.generation)
            pending.update(applied=True, expired_revision=revision)
            self.save()

    def refresh_evidence(self):
        from vaultrewind.storage.credentials import credential_context
        from vaultrewind.storage.drive import token_expiry
        injection = self.state['expiry_injection']
        before = self.box.decrypt(injection['expired_envelope'], context=credential_context(self.destination))
        stored, after = self.credential()
        require(stored.generation == injection['generation'] and digest(after['grant_id']) == injection['grant_sha256']
                and stored.revision > injection['expired_revision'] and after.get('token_refreshed_at')
                and after.get('token_refreshed_at') != before.get('token_refreshed_at')
                and token_expiry(after['token']) > datetime.now(UTC) + timedelta(minutes=1)
                and after['token']['access_token'] != before['token']['access_token'],
                'REAL_RCLONE_REFRESH_PERSISTENCE_NOT_PROVEN')
        self.state['refresh'] = {'real_rclone_access_token_refresh_persisted_in_encrypted_sql': True,
            'generation_and_grant_preserved': True, 'revision_advanced': True,
            'access_token_changed': True, 'expiry_future': True}
        self.save()

    def submit_job(self, stage, path, body=None, *, submission_tag=None):
        from sqlalchemy import select

        from vaultrewind.server.models import Job
        tag = ':' + submission_tag if submission_tag else ''
        record = self.state['steps'].setdefault(stage, {'idempotency_key': f'drive-drill:{self.run_id}:{stage}{tag}'})
        action = submission_action(record)
        if action == 'lookup_existing':
            with self.sessions() as db:
                jobs = list(db.scalars(select(Job).where(Job.idempotency_key == record['idempotency_key'])))
            require(len(jobs) == 1, 'SUBMISSION_RESPONSE_UNRESOLVED_DO_NOT_REPEAT')
            record['job_id'] = jobs[0].id
            self.save()
        elif action == 'submit_once':
            record['attempted'] = True
            self.save()
            response = self.request('POST', path, body or {}, expected=202, key=record['idempotency_key'])
            record['job_id'] = response['job_id']
            self.save()
        return record['job_id']

    def wait_job(self, stage, timeout=1800):
        record = self.state['steps'][stage]
        deadline = time.monotonic() + timeout
        last = None
        while time.monotonic() < deadline:
            job = self.request('GET', '/jobs/' + record['job_id'])
            observed = (job['state'], job['phase'])
            if observed != last:
                print(json.dumps({'step': stage, 'job_id': job['id'], 'state': observed[0], 'phase': observed[1]}), flush=True)
                last = observed
            if stage == 'backup' and job['phase'] == 'committing_copies' and not record.get('source_running_during_cloud'):
                record['source_running_during_cloud'] = self.source_witness()['running']
                self.save()
            if job['state'] in TERMINAL:
                fields = ('id', 'kind', 'instance_id', 'state', 'phase', 'error_code', 'content_commit',
                          'required_copy_outcome', 'source_service_outcome', 'target_activation_outcome')
                record['job'] = {key: job.get(key) for key in fields}
                record['result'] = {key: value for key, value in job.get('result', {}).items() if key in {
                    'snapshot_id', 'safety_snapshot_id', 'application_started', 'user_login_tested',
                    'restored_bytes_verified', 'candidate_validated', 'active_generation', 'activation_started'}}
                self.save()
                require(job['state'] == 'succeeded', 'JOB_NOT_SUCCESSFUL_' + stage.upper())
                return job
            time.sleep(2)
        raise DrillError('JOB_WAIT_TIMEOUT_RECONCILE_EXISTING_ID')

    def patch_policy(self, body):
        view = self.request('GET', f'/instances/{SOURCE_ID}/policy')
        return self.request('PATCH', f'/instances/{SOURCE_ID}/policy', body,
                            headers={'If-Match': f'"{view["revision"]}"'})

    def restore_policy(self):
        if 'original_policy' not in self.state or self.state.get('policy_restored'):
            return
        self.idle_source(timeout=120)
        restored = self.patch_policy(policy_body(self.state['original_policy']))
        require(policy_body(restored) == policy_body(self.state['original_policy']), 'ORIGINAL_POLICY_NOT_RESTORED')
        require(all(restored.get(key) == self.state['original_policy'].get(key)
                    for key in ('next_verify_at', 'next_test_at')), 'VERIFY_SCHEDULE_CHANGED')
        self.state['policy_restored'] = True
        self.save()

    def source_witness(self):
        """Read the exact local fixture only after ROOTGO; never read arbitrary Docker environments."""
        import subprocess

        from vaultrewind.core.manifest import inventory
        result = subprocess.run(['docker', 'inspect', 'vr-ssh-source'], capture_output=True, timeout=30, check=False)
        require(result.returncode == 0, 'SOURCE_FIXTURE_INSPECTION_FAILED')
        descriptor = json.loads(result.stdout)[0]
        label = (descriptor['Config'].get('Labels') or {}).get('org.vaultrewind.instance')
        mounts = [m for m in descriptor['Mounts'] if m['Destination'] == '/data']
        require(label == SOURCE_ID and len(mounts) == 1 and mounts[0]['Type'] == 'bind' and
                mounts[0]['Source'] == str(SOURCE) and SOURCE.resolve() == SOURCE, 'EXACT_SYNTHETIC_SOURCE_REQUIRED')
        require(descriptor['State']['Running'], 'SOURCE_NOT_RUNNING')
        fields = ('path', 'type', 'sha256', 'size', 'uid', 'gid', 'mode', 'link_target', 'hardlink_to', 'xattrs')
        entries = [{key: item[key] for key in fields if key in item} for item in inventory(SOURCE)]
        return {'running': True, 'container_id': descriptor['Id'], 'started_at': descriptor['State']['StartedAt'],
                'whole_inventory_sha256': digest(entries)}

    def backup(self):
        self.verify_destination()
        if 'original_policy' not in self.state:
            self.idle_source()
            original = self.request('GET', f'/instances/{SOURCE_ID}/policy')
            require(not original['enabled'] and any(e['backend'] == 'local' and e['required']
                    for e in original['destinations']), 'DISABLED_POLICY_AND_REQUIRED_VALID_LOCAL_REQUIRED')
            self.state['original_policy'] = original
            self.save()
        if 'backup' not in self.state['steps']:
            self.idle_source()
            chosen = [{key: entry[key] for key in ('destination_id', 'required')}
                      for entry in self.state['original_policy']['destinations']]
            chosen = [entry for entry in chosen if entry['destination_id'] != self.destination]
            chosen.append({'destination_id': self.destination, 'required': True})
            self.patch_policy({'enabled': False, 'destinations': chosen})
            self.state['policy_restored'] = False
            self.save()
            self.force_expiry()
        self.submit_job('backup', f'/instances/{SOURCE_ID}/backups', {'label': 'Dedicated synthetic Drive drill'})
        job = self.wait_job('backup')
        require(job['source_service_outcome'] == 'running' and job['required_copy_outcome'] == 'complete',
                'BACKUP_COPY_OR_SOURCE_OUTCOME_INVALID')
        snapshot = self.request('GET', '/snapshots/' + job['result']['snapshot_id'])
        cloud = [c for c in snapshot['copies'] if c['destination_id'] == self.destination and c['backend'] == 'drive']
        local = [c for c in snapshot['copies'] if c['backend'] == 'local' and c['state'] == 'complete']
        require(len(cloud) == 1 and cloud[0]['state'] == 'complete' and local, 'BOTH_COMPLETE_COPIES_REQUIRED')
        self.state.update(snapshot_id=snapshot['id'], drive_copy_id=cloud[0]['id'], local_copy_id=local[0]['id'])
        self.save()
        if not self.state.get('refresh'):
            self.refresh_evidence()
        self.readback('drive_readback', self.state['drive_copy_id'], 'drive')
        self.readback('local_readback', self.state['local_copy_id'], 'local')
        self.capture_journal()

    def capture_journal(self):
        ident = self.state['steps']['backup']['job_id']
        value = json.loads(private_read(Path('/var/lib/vaultrewind-helper/journals') / (ident + '.json')))
        require(value['instance_id'] == SOURCE_ID and value.get('source_service_outcome') == 'running',
                'SOURCE_JOURNAL_RECOVERY_UNPROVEN')
        history = [{key: event[key] for key in ('phase', 'at')} for event in value['history']]
        phases = [entry['phase'] for entry in history]
        require('validating' in phases and 'captured' in phases and phases.index('validating') < phases.index('captured'),
                'SOURCE_NOT_RESUMED_BEFORE_SEAL_TRANSFER_CLOUD')
        self.state['source_recovery'] = {'resumed_before_normalization_transfer_cloud': True, 'history': history}
        self.save()

    def readback(self, stage, copy_id, backend):
        from sqlalchemy import select

        from vaultrewind.core.manifest import sha256_file, verify_snapshot
        from vaultrewind.core.sqlite import validate_sqlite
        from vaultrewind.server.models import Repository, Snapshot, SnapshotCopy, StorageDestination
        grant_hash = None
        if stage == 'reconnect_historical_readback':
            _, credential = self.credential()
            grant_hash = digest(credential['grant_id'])
        previous = self.state.get(stage, {})
        if previous.get('complete') and (grant_hash is None or previous.get('grant_sha256') == grant_hash):
            return
        with self.sessions() as db:
            row = db.execute(select(SnapshotCopy, Repository, StorageDestination).join(
                Repository, Repository.id == SnapshotCopy.repository_id).join(
                StorageDestination, StorageDestination.id == Repository.destination_id).where(SnapshotCopy.id == copy_id)).one()
            copy_row, repository, destination = row
            snapshot = db.get(Snapshot, self.state['snapshot_id'])
            require(copy_row.snapshot_id == snapshot.id and snapshot.instance_id == SOURCE_ID and
                    repository.instance_id == SOURCE_ID and copy_row.state == 'complete' and destination.backend == backend,
                    'EXACT_COMPLETE_COPY_REQUIRED')
            if backend == 'drive':
                require(destination.id == self.destination, 'WRONG_DRIVE_DESTINATION')
            repo_id, restic_id, expected = repository.id, copy_row.restic_snapshot_id, snapshot.manifest_hash
        # A fresh grant must perform a fresh provider read, not verify an older local cache.
        suffix = '-' + grant_hash[:24] if grant_hash else ''
        work = self.root / (stage + suffix + '-adapter')
        work.mkdir(mode=0o700, exist_ok=True)
        target = self.root / (stage + suffix + '-restored')
        begun = time.monotonic()
        if target.exists():
            result = verify_snapshot(target, expected)
        else:
            with self.adapters.repository(repo_id, work) as repo:
                repo.restore(restic_id, target, expected_manifest_hash=expected)
            result = verify_snapshot(target, expected)
        manifest = result['manifest']
        require(manifest['snapshot_uuid'] == self.state['snapshot_id'] and manifest['instance_uuid'] == SOURCE_ID,
                'READBACK_MANIFEST_IDENTITY_MISMATCH')
        image = target / 'images/vaultwarden.tar'
        require(sha256_file(image) == manifest['image_archive_hash'], 'SAVED_IMAGE_HASH_MISMATCH')
        sqlite = validate_sqlite(target / 'data')
        require(not (target / 'data/db.sqlite3-wal').exists() and not (target / 'data/db.sqlite3-shm').exists(),
                'STANDALONE_NORMALIZED_DATABASE_REQUIRED')
        files = {entry['path']: entry['sha256'] for entry in manifest['inventory'] if entry['type'] == 'file'}
        private_write(self.root / (stage + '-manifest.json'), manifest)
        self.state[stage] = {'complete': True, 'backend': backend, 'snapshot_id': snapshot.id, 'copy_id': copy_id,
            'repository_id': repo_id, 'manifest_hash': expected, 'whole_file_map_sha256': digest(files),
            'grant_sha256': grant_hash,
            'file_count': len(files), 'logical_bytes': result['logical_bytes'],
            'restic_restore_verify_and_manifest_seconds': round(time.monotonic() - begun, 6),
            'restored_bytes_verified': True, 'saved_image_inventory_verified': True,
            'sqlite_integrity': sqlite['database_integrity'],
            'application_started': False, 'user_login_tested': False}
        require(self.state[stage]['sqlite_integrity'] == 'ok', 'SQLITE_INTEGRITY_NOT_PROVEN')
        if 'drive_readback' in self.state and stage != 'drive_readback':
            require(self.state[stage]['whole_file_map_sha256'] == self.state['drive_readback']['whole_file_map_sha256'],
                    'HISTORICAL_COPY_CONTENT_CHANGED')
        self.save()

    def restore_alternate(self):
        if not self.args.target_id or self.state.get('alternate_restore', {}).get('complete'):
            return
        require_execution(self.args)
        import httpx
        from sqlalchemy import select

        from vaultrewind.server.models import Host, Instance, Job, RestorePlan
        with self.sessions() as db:
            source, target = db.get(Instance, SOURCE_ID), db.get(Instance, self.args.target_id)
            require(target is not None and target.id == ALTERNATE_ID and target.host_id != source.host_id and
                    target.container_id and not target.is_runner and target.readiness == 'ready',
                    'PREPARED_EXISTING_ALTERNATE_REQUIRED')
            host = db.get(Host, target.host_id)
            require(host.endpoint == '127.0.0.1' and host.port == 22229, 'SERIALIZED_FIXTURE_VM_REQUIRED')
        if 'source_before_restore' not in self.state:
            self.state['source_before_restore'] = self.source_witness()
            self.save()
        if 'restore_plan' not in self.state:
            require(not self.state.get('restore_plan_attempted'), 'RESTORE_PLAN_RESPONSE_UNRESOLVED')
            self.state['restore_plan_attempted'] = True
            self.save()
            plan = self.request('POST', '/snapshots/' + self.state['snapshot_id'] + '/restore-plans',
                {'target_id': self.args.target_id, 'copy_id': self.state['drive_copy_id'],
                 'start_on_completion': True}, expected=201)
            require(plan['target_id'] == ALTERNATE_ID and plan['copy_id'] == self.state['drive_copy_id'] and
                    plan['safety_snapshot_required'], 'DRIVE_COPY_AND_LOCAL_SAFETY_PLAN_REQUIRED')
            self.state['restore_plan'] = {'id': plan['id'], 'target_id': ALTERNATE_ID,
                'copy_id': plan['copy_id'], 'expires_at': plan['expires_at'],
                'encrypted_token': self.box.encrypt({'token': plan['confirmation_token']},
                                                    context='drive-drill:' + self.run_id + ':restore-plan')}
            self.save()
        plan = self.state['restore_plan']
        token = self.box.decrypt(plan['encrypted_token'], context='drive-drill:' + self.run_id + ':restore-plan')['token']
        self.secrets_in_memory.append(token)
        self.submit_job('restore', '/restore-plans/' + plan['id'] + '/execute', {'confirmation_token': token})
        job = self.wait_job('restore')
        with self.sessions() as db:
            executed = db.get(Job, job['id'])
            bound = db.scalar(select(RestorePlan).where(RestorePlan.id == plan['id']))
            require(executed.request.get('copy_id') == self.state['drive_copy_id'] and
                    bound.copy_id == self.state['drive_copy_id'] and executed.instance_id == ALTERNATE_ID,
                    'EXECUTED_RESTORE_NOT_BOUND_TO_SELECTED_DRIVE_COPY')
        require(job['target_activation_outcome'] == 'complete' and job['result'].get('application_started') and
                job['result'].get('restored_bytes_verified'), 'ACTUAL_ALTERNATE_RESTORE_NOT_PROVEN')
        safety_id = job['result'].get('safety_snapshot_id')
        require(safety_id, 'MANDATORY_LOCAL_SAFETY_SNAPSHOT_MISSING')
        safety = self.request('GET', '/snapshots/' + safety_id)
        require(safety['safety'] and safety['pinned'] and any(c['backend'] == 'local' and c['state'] == 'complete'
                for c in safety['copies']), 'PINNED_COMPLETE_LOCAL_SAFETY_REQUIRED')
        # Do not forward controller cookies or CSRF headers to the recovered application.
        with httpx.Client(timeout=15, trust_env=False, follow_redirects=False) as public:
            for suffix in ('/alive', '/api/config'):
                response = public.get(self.args.target_public_origin + suffix)
                require(response.status_code == 200, 'ALTERNATE_PUBLIC_READINESS_UNPROVEN')
                if suffix == '/api/config':
                    require(isinstance(response.json(), dict), 'ALTERNATE_CONFIG_RESPONSE_INVALID')
        after = self.source_witness()
        require(after == self.state['source_before_restore'], 'ORIGINAL_SOURCE_CHANGED_DURING_ALTERNATE_RESTORE')
        self.state['alternate_restore'] = {'complete': True, 'job_id': job['id'], 'target_id': ALTERNATE_ID,
            'selected_drive_copy_id': self.state['drive_copy_id'], 'safety_snapshot_id': safety_id,
            'pinned_complete_local_safety': True, 'source_started_at_and_whole_hash_unchanged': True,
            'public_alive_config_200': True, 'application_started': True, 'user_login_tested': False}
        self.save()

    def reconnect(self):
        require(self.state.get('drive_readback', {}).get('complete'), 'ROUNDTRIP_MUST_COMPLETE_FIRST')
        if self.args.revoke_dedicated_grant:
            self.revoke_grant()
            return
        _, credential = self.verify_destination()
        baseline = self.state.get('revocation', {}).get('old_grant_sha256') or self.state['baseline_grant_sha256']
        current_grant = digest(credential['grant_id'])
        require(current_grant != baseline, 'COMPLETE_FRESH_RECONNECT_IN_APP_FIRST')
        if self.state.get('reconnect_attempt_grant_sha256') not in {None, current_grant}:
            previous = self.state['steps'].get('reconnect_probe', {})
            require(not previous or previous.get('job', {}).get('state') in TERMINAL,
                    'PREVIOUS_RECONNECT_JOB_NEEDS_RECONCILIATION')
            self.state.setdefault('previous_reconnect_attempts', []).append({
                'grant_sha256': self.state['reconnect_attempt_grant_sha256'], 'probe': previous,
                'readback': self.state.pop('reconnect_historical_readback', None),
                'proof': self.state.pop('reconnect', None)})
            self.state['steps'].pop('reconnect_probe', None)
        self.state['reconnect_attempt_grant_sha256'] = current_grant
        self.save()
        # SQL-backed adapters use the current app credential, not an old recovery-kit grant.
        self.submit_job('reconnect_probe', f'/storage-destinations/{self.destination}/test',
                        submission_tag=current_grant[:16])
        self.wait_job('reconnect_probe')
        self.readback('reconnect_historical_readback', self.state['drive_copy_id'], 'drive')
        self.state['reconnect'] = {'complete': True, 'fresh_grant': True, 'same_historical_snapshot': True,
                                   'same_repository_and_copy': True}
        self.state['awaiting_private_ui_reconnect'] = False
        self.save()

    def revoke_grant(self):
        """Optional separate scope; invalidate locally before any Google revocation call."""
        require_execution(self.args)
        if self.state.get('revocation', {}).get('source_unchanged_and_local_copy_verified'):
            print('Revocation already completed for this run; continue the ordinary reconnect phase.', flush=True)
            return
        import httpx

        from vaultrewind.core.errors import VaultRewindError
        from vaultrewind.storage.credentials import credential_context
        from vaultrewind.storage.drive import GoogleApi, GoogleClient
        self.readback('pre_revocation_local', self.state['local_copy_id'], 'local')
        before_source = self.source_witness()
        revocation = self.state.setdefault('revocation', {})
        context = 'drive-drill:' + self.run_id + ':old-grant'
        with self.credential_exclusive():
            stored, credential = self.credential()
            if not revocation.get('locally_invalidated'):
                require(not revocation.get('invalidation_attempted'), 'REVOCATION_CAS_RESPONSE_REQUIRES_REVIEW')
                revocation.update(invalidation_attempted=True, old_grant_sha256=digest(credential['grant_id']),
                    encrypted_old_credential=self.box.encrypt(credential, context=context))
                self.save()
                replacement = {**credential, 'grant_id': str(uuid4()), 'revoked': True,
                               'revoked_at': datetime.now(UTC).isoformat()}
                envelope = self.box.encrypt(replacement, context=credential_context(self.destination))
                self.store.compare_and_swap(self.destination, envelope, stored.revision,
                                            expected_generation=stored.generation)
                revocation['locally_invalidated'] = True
                self.state['awaiting_private_ui_reconnect'] = True
                self.save()
        old = self.box.decrypt(revocation['encrypted_old_credential'], context=context)
        with httpx.Client(timeout=30, trust_env=False, follow_redirects=False) as http:
            api = GoogleApi(http)
            if not revocation.get('google_revoke_acknowledged'):
                require(not revocation.get('google_revoke_attempted'), 'REVOCATION_RESPONSE_UNRESOLVED')
                revocation['google_revoke_attempted'] = True
                self.save()
                require(api.revoke(old['token']['refresh_token']), 'GOOGLE_REVOCATION_NOT_ACKNOWLEDGED')
                revocation['google_revoke_acknowledged'] = True
                self.save()
            try:
                api.refresh(GoogleClient(old['client_id'], old['client_secret']), old['token']['refresh_token'])
            except VaultRewindError as error:
                require(error.code == 'STORAGE_AUTH_EXPIRED', 'REVOKED_GOOGLE_REFRESH_DID_NOT_REPORT_AUTH_EXPIRED')
                revocation['actual_google_refresh_error'] = error.code
            else:
                raise DrillError('OLD_GOOGLE_GRANT_STILL_REFRESHABLE')
        require(self.source_witness() == before_source, 'SOURCE_CHANGED_DURING_REVOCATION')
        revocation['source_unchanged_and_local_copy_verified'] = True
        self.state['awaiting_private_ui_reconnect'] = True
        self.save()
        print('Dedicated grant revoked; complete one fresh Reconnect in the app before reconnect readback.', flush=True)

    def publish(self):
        steps = {name: {key: value for key, value in record.items() if key in {
            'job_id', 'job', 'result', 'source_running_during_cloud'}} for name, record in self.state['steps'].items()}
        revoked = self.state.get('revocation', {})
        reconnect_complete = bool(self.state.get('reconnect', {}).get('complete') and
                                  not self.state.get('awaiting_private_ui_reconnect'))
        complete = bool(reconnect_complete and self.state.get('alternate_restore', {}).get('complete'))
        report = {'provider': 'google_drive', 'scope': 'drive.file', 'synthetic_only': True,
            'dedicated_test_account_acknowledged': True, 'google_account_identity_independently_verified': False,
            'recorded_at': datetime.now(UTC).isoformat(), 'run_id': self.run_id, 'destination_id': self.destination,
            'result': 'roundtrip_restore_reconnect_proven' if complete else 'partial',
            'AC14_release_verified': False, 'retention_live_proven': False,
            'note': 'Retention is not part of this drill; full AC14 release verification requires its separate evidence.',
            'snapshot_id': self.state.get('snapshot_id'), 'drive_copy_id': self.state.get('drive_copy_id'),
            'jobs': steps, 'refresh': self.state.get('refresh'), 'source_recovery': self.state.get('source_recovery'),
            'drive_readback': self.state.get('drive_readback'), 'local_readback': self.state.get('local_readback'),
            'alternate_restore': self.state.get('alternate_restore'), 'reconnect': self.state.get('reconnect'),
            'reconnect_historical_readback': self.state.get('reconnect_historical_readback'),
            'optional_revocation': {key: revoked[key] for key in (
                'locally_invalidated', 'google_revoke_acknowledged', 'actual_google_refresh_error',
                'source_unchanged_and_local_copy_verified') if key in revoked},
            'original_policy_restored': self.state.get('policy_restored', False),
            'previous_reconnect_attempts': self.state.get('previous_reconnect_attempts', []),
            'failures': self.state['failures'], 'user_login_tested': False,
            'awaiting_private_ui_reconnect': bool(self.state.get('awaiting_private_ui_reconnect'))}
        text = json.dumps(report, indent=2) + '\n'
        require(all(secret not in text for secret in self.secrets_in_memory if len(secret) >= 8),
                'PUBLIC_EVIDENCE_SECRET_DETECTED')
        path = PROJECT / 'docs/evidence/drive.json'
        path.write_text(text)

    def execute(self):
        try:
            if self.args.phase == 'roundtrip':
                self.backup()
                self.restore_alternate()
            else:
                self.reconnect()
                if not self.args.revoke_dedicated_grant:
                    self.restore_alternate()
        except Exception as error:  # noqa: BLE001 - raw exceptions may contain credentials.
            code = str(error) if isinstance(error, DrillError) else getattr(error, 'code', 'DRILL_INTERNAL_FAILURE')
            if not isinstance(code, str) or not re.fullmatch(r'[A-Z0-9_]{1,160}', code):
                code = 'DRILL_INTERNAL_FAILURE'
            self.state['failures'].append({'phase': self.args.phase, 'code': code, 'at': datetime.now(UTC).isoformat()})
            self.save()
            raise DrillError(code) from None
        finally:
            try:
                self.restore_policy()
            except Exception as error:  # noqa: BLE001 - record cleanup failures without private exception text.
                code = str(error) if isinstance(error, DrillError) else 'POLICY_RESTORE_FAILED'
                self.state['failures'].append({'phase': 'policy_restore', 'code': code,
                                               'at': datetime.now(UTC).isoformat()})
                self.state['policy_restored'] = False
                self.save()
                raise DrillError(code) from None
            finally:
                self.publish()


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dedicated-test-account', action='store_true', required=True)
    parser.add_argument('--destination-id', type=identifier, required=True)
    parser.add_argument('--phase', choices=('roundtrip', 'reconnect'), required=True)
    parser.add_argument('--run-id', type=identifier)
    parser.add_argument('--credential-state-dir', type=Path,
                        help='Only if the native worker explicitly configures provider_credential_state_dir.')
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--root-go', default='')
    parser.add_argument('--target-id', type=identifier)
    parser.add_argument('--target-go', default='')
    parser.add_argument('--target-public-origin', type=loopback_origin)
    parser.add_argument('--revoke-dedicated-grant', action='store_true')
    parser.add_argument('--revocation-go', default='')
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    if not args.execute:
        # Preparation is deliberately pure: no runtime files or clients are opened.
        print(json.dumps({'status': 'prepared_external_actions_parked', 'phase': args.phase,
            'destination_id': args.destination_id, 'runtime_directory': '.runtime/drive-proof/' + (args.run_id or args.destination_id),
            'requires': ['later ROOTGO', 'dedicated destination authorized privately in app',
                         'separate ROOTGO_TARGET for alternate restore', 'optional separate ROOTGO_REVOKE'],
            'network_sql_provider_ssh_docker_calls': 0, 'evidence_written': False}), flush=True)
        return 0
    os.umask(0o077)
    try:
        DriveDrill(args).execute()
    except DrillError as error:
        print(str(error), flush=True)
        return 1
    except Exception:  # noqa: BLE001 - no private file/SQL/provider exception details in logs.
        print('DRILL_INITIALIZATION_FAILED_PRIVATE_DETAILS_WITHHELD', flush=True)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

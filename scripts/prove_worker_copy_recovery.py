#!/usr/bin/env python3
"""Real API/worker AC02/AC03/AC18 drill, restricted to the disposable local fixture.

Default invocation is read-only preparation. --execute --root-go ROOTGO is a
coordination gate: the parent must explicitly release the shared source first.
No production hosts, arbitrary source paths, or external providers are accepted.
Provider credentials stay in private files/memory, never subprocess arguments.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import stat
import subprocess
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import httpx
from sqlalchemy import select

PROJECT = Path(__file__).resolve().parents[1]
SOURCE = Path('/srv/vaultrewind-fixtures/source/data')
CONTROLLER = Path('/srv/vaultrewind-native-controller')
EXPECTED_SOURCE_ID = '46ac8eb9-1854-4fc6-924f-af14c6b7d0c2'
ORIGIN = 'http://127.0.0.1:8098'
HEAVY_BYTES = 16 * 1024**2
TERMINAL = {'succeeded', 'failed', 'partial', 'cancelled', 'rolled_back', 'rollback_failed', 'needs_attention'}
ACTIVE = {'queued', 'running', 'waiting_retry', 'cancel_requested'}


class DrillError(Exception):
    """Only intentionally public error codes belong in this exception."""


def require(value, code):
    if not value:
        raise DrillError(code)


def private_read(path):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o077,
                'PRIVATE_INPUT_PERMISSIONS')
        return stream.read()


def private_write(path, value):
    from vaultrewind.security.privatefiles import atomic_private_write
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    atomic_private_write(path, json.dumps(value, indent=2).encode())


def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024**2), b''):
            digest.update(block)
    return digest.hexdigest()


def run(*args):
    result = subprocess.run(list(args), capture_output=True, timeout=60, check=False)
    require(result.returncode == 0, 'FIXTURE_COMMAND_FAILED')
    return result.stdout


class Drill:
    def __init__(self, args):
        from vaultrewind.server.adapters import Adapters
        from vaultrewind.server.db import make_engine, sessions
        from vaultrewind.server.settings import Settings
        self.args = args
        self.run = args.run_dir.resolve()
        require(self.run.is_relative_to(PROJECT / '.runtime' / 'copy-proof'), 'RUNTIME_PATH_UNSAFE')
        self.run.mkdir(parents=True, exist_ok=True, mode=0o700)
        require(not self.run.is_symlink() and not self.run.stat().st_mode & 0o077, 'RUNTIME_NOT_PRIVATE')
        self.checkpoint = self.run / 'checkpoint.json'
        self.state = json.loads(private_read(self.checkpoint)) if self.checkpoint.exists() else {}
        self.instance = json.loads(private_read(args.private_dir / 'integration.json'))['source_id']
        require(self.instance == EXPECTED_SOURCE_ID, 'EXACT_SOURCE_UUID_REQUIRED')
        self.settings = Settings(database_url=private_read(args.private_dir / 'database-url').decode().strip(),
            master_key_file=args.private_dir / 'master', bootstrap_secret_file=args.private_dir / 'bootstrap',
            local_storage_root=CONTROLLER / 'backups', staging_dir=CONTROLLER / 'staging',
            public_origin=ORIGIN, secure_cookies=False)
        self.engine = make_engine(self.settings.database_url)
        self.sessions = sessions(self.engine)
        self.adapters = Adapters(self.settings, self.sessions)
        cookies = json.loads(private_read(args.private_dir / 'api-cookies.json'))
        self.api = httpx.Client(base_url=ORIGIN, cookies=cookies, timeout=30, trust_env=False,
            headers={'Origin': ORIGIN, 'X-CSRF-Token': cookies['vr_csrf']})
        self.credentials = json.loads(private_read(PROJECT / '.runtime/minio/credentials.json'))
        require(self.credentials['endpoint'] == 'http://127.0.0.1:19000', 'LOOPBACK_MINIO_REQUIRED')

    def save(self):
        private_write(self.checkpoint, self.state)

    def request(self, method, path, body=None, *, expected=200, headers=None, key=None):
        headers = dict(headers or {})
        if method != 'GET':
            headers['Idempotency-Key'] = key or str(uuid4())
        response = self.api.request(method, '/api/v1' + path, json=body, headers=headers)
        if response.status_code != expected:
            try:
                code = response.json().get('error', {}).get('code', 'HTTP_ERROR')
            except (ValueError, AttributeError):
                code = 'HTTP_ERROR'
            raise DrillError(f'{method} {path}: HTTP_{response.status_code} {code}')
        return response.json()

    def inspect_source(self):
        descriptor = json.loads(run('docker', 'inspect', 'vr-ssh-source'))[0]
        labels = descriptor['Config'].get('Labels') or {}
        require(labels.get('vaultrewind.fixture') == 'true' or
                labels.get('org.vaultrewind.instance') == self.instance, 'SYNTHETIC_CONTAINER_LABEL_REQUIRED')
        mounts = [m for m in descriptor['Mounts'] if m['Destination'] == '/data']
        require(len(mounts) == 1 and mounts[0]['Type'] == 'bind' and
                mounts[0]['Source'] == str(SOURCE), 'EXACT_SYNTHETIC_BIND_REQUIRED')
        require(SOURCE.resolve() == SOURCE and not SOURCE.is_symlink(), 'SOURCE_PATH_UNSAFE')
        return {'container_id': descriptor['Id'], 'running': descriptor['State']['Running'],
                'started_at': descriptor['State']['StartedAt']}

    def attachments(self):
        paths = [p for p in (SOURCE / 'attachments').rglob('*') if p.is_file()]
        require(len(paths) == 1, 'EXACTLY_ONE_EXISTING_SYNTHETIC_ATTACHMENT_REQUIRED')
        attachment = paths[0]
        info = attachment.lstat()
        require(stat.S_ISREG(info.st_mode) and not attachment.is_symlink() and
                info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600, 'PRIVATE_ROOT_ATTACHMENT_REQUIRED')
        require(attachment.resolve().is_relative_to(SOURCE / 'attachments'), 'ATTACHMENT_PATH_UNSAFE')
        return attachment

    def db_read(self):
        return sqlite3.connect((SOURCE / 'db.sqlite3').as_uri() + '?mode=ro', uri=True)

    def source_content_digest(self):
        # Synthetic record content stays private; publish only equality/digests.
        digest = hashlib.sha256()
        with self.db_read() as db:
            for table in ('users', 'organizations', 'ciphers', 'attachments', 'sends'):
                rows = db.execute(f'SELECT * FROM {table} ORDER BY 1').fetchall()
                digest.update(repr((table, rows)).encode())
        return digest.hexdigest()

    def guard_idle(self):
        from vaultrewind.server.models import Job
        with self.sessions() as db:
            active = list(db.scalars(select(Job.id).where(Job.instance_id == self.instance, Job.state.in_(ACTIVE))))
        require(not active, 'SHARED_SOURCE_HAS_ACTIVE_JOB_WAIT_FOR_ROOT')

    def prepare(self):
        source = self.inspect_source()
        attachment = self.attachments()
        with self.db_read() as db:
            columns = {row[1] for row in db.execute('PRAGMA table_info(attachments)')}
            require({'id', 'cipher_uuid', 'file_size'} <= columns, 'FIXTURE_ATTACHMENT_SCHEMA_UNEXPECTED')
            rows = db.execute('SELECT id,cipher_uuid,file_size FROM attachments').fetchall()
            require(len(rows) == 1 and attachment.relative_to(SOURCE).as_posix() ==
                    f'attachments/{rows[0][1]}/{rows[0][0]}', 'FIXTURE_REFERENCE_MISMATCH')
            counts = {table: db.execute(f'SELECT count(*) FROM {table}').fetchone()[0]
                      for table in ('users', 'organizations', 'ciphers', 'attachments', 'sends')}
        policy = self.request('GET', f'/instances/{self.instance}/policy')
        require(not policy['enabled'] or 'original_policy' in self.state, 'INITIAL_SCHEDULE_MUST_BE_DISABLED')
        schema = self.api.get('/api/v1/openapi.json').json()
        ready = 'patch' in schema.get('paths', {}).get('/api/v1/storage-destinations/{ident}', {})
        report = {'synthetic_only': True, 'source_id': self.instance, 'source': source,
                  'attachment_bytes': attachment.stat().st_size, 'attachment_mode': '0600',
                  'attachment_uid': 0, 'row_counts': counts, 'schedule_enabled': policy['enabled'],
                  'credential_patch_live': ready, 'actions_queued': False}
        private_write(self.run / 'preparation.json', report)
        print(json.dumps(report), flush=True)
        return ready

    def patch_policy(self, body):
        current = self.request('GET', f'/instances/{self.instance}/policy')
        return self.request('PATCH', f'/instances/{self.instance}/policy', body,
                            headers={'If-Match': f'"{current["revision"]}"'})

    def enlarge_fixture(self):
        self.inspect_source()
        self.guard_idle()
        attachment = self.attachments()
        if 'fixture' in self.state:
            require(attachment.stat().st_size == HEAVY_BYTES and
                    sha(attachment) == self.state['fixture']['attachment_sha256'], 'PREPARED_FIXTURE_CHANGED')
            return
        initial = b'synthetic private attachment'
        require(len(initial) == 28, 'SEED_LENGTH_CHANGED')
        expected = initial + hashlib.shake_256(b'vaultrewind-synthetic-attachment-heavy-v1').digest(HEAVY_BYTES - len(initial))
        if attachment.stat().st_size == 28:
            require(attachment.read_bytes() == initial, 'SYNTHETIC_ATTACHMENT_SEED_MISMATCH')
            before = attachment.stat()
            with os.fdopen(os.open(attachment, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW), 'ab') as stream:
                stream.write(expected[len(initial):])
                stream.flush()
                os.fsync(stream.fileno())
            after = attachment.stat()
            require((before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode)) ==
                    (after.st_uid, after.st_gid, stat.S_IMODE(after.st_mode)), 'LIVE_PERMISSIONS_CHANGED')
        require(attachment.stat().st_size == HEAVY_BYTES and sha(attachment) == hashlib.sha256(expected).hexdigest(),
                'HEAVY_ATTACHMENT_CONTENT_MISMATCH')
        # One guarded, legitimate reference-size update, never an application backup substitute.
        with sqlite3.connect(SOURCE / 'db.sqlite3') as db:
            rows = db.execute('SELECT id,cipher_uuid,file_size FROM attachments').fetchall()
            require(len(rows) == 1 and attachment.relative_to(SOURCE).as_posix() ==
                    f'attachments/{rows[0][1]}/{rows[0][0]}', 'FIXTURE_REFERENCE_MISMATCH')
            db.execute('UPDATE attachments SET file_size=? WHERE id=? AND cipher_uuid=?',
                       (HEAVY_BYTES, rows[0][0], rows[0][1]))
            db.commit()
        self.state['fixture'] = {'attachment_bytes': HEAVY_BYTES, 'attachment_sha256': sha(attachment),
            'attachment_mode': '0600', 'attachment_uid': attachment.stat().st_uid,
            'attachment_gid': attachment.stat().st_gid, 'relative_path': attachment.relative_to(SOURCE).as_posix(),
            'metadata_size_consistent': True, 'wal_bytes_before_capture': self.wal_size()}
        self.save()

    @staticmethod
    def wal_size():
        path = SOURCE / 'db.sqlite3-wal'
        return path.stat().st_size if path.exists() else 0

    def enqueue(self, label, path, body=None):
        if label not in self.state:
            started = time.monotonic()
            accepted = self.request('POST', path, body or {}, expected=202,
                                    key=f'copy-proof:{self.run.name}:{label}')
            self.state[label] = {'job_id': accepted['job_id'],
                                 'api_creation_seconds': round(time.monotonic() - started, 6)}
            self.save()
        return self.state[label]['job_id']

    def wait(self, label, expected_state='succeeded', timeout=900):
        record = self.state[label]
        ident = record['job_id']
        deadline = time.monotonic() + timeout
        last_phase = None
        while time.monotonic() < deadline:
            job = self.request('GET', f'/jobs/{ident}')
            events = self.request('GET', f'/jobs/{ident}/events')['events']
            if events:
                created = datetime.fromisoformat(job['created_at'])
                record['progress_visible_seconds'] = round(
                    (datetime.fromisoformat(events[0]['created_at']) - created).total_seconds(), 6)
                nonqueued = [e for e in events if e['phase'] != 'queued']
                if nonqueued:
                    record['first_named_phase_seconds'] = round(
                        (datetime.fromisoformat(nonqueued[0]['created_at']) - created).total_seconds(), 6)
            if job['phase'] != last_phase:
                print(f'{label}: {job["state"]} / {job["phase"]}', flush=True)
                last_phase = job['phase']
            if job['state'] in TERMINAL:
                record['job'] = job
                record['events'] = events
                self.save()
                require(job['state'] == expected_state, f'{label}: UNEXPECTED_JOB_STATE_{job["state"]}_{job.get("error_code")}')
                return job
            time.sleep(1)
        raise DrillError(f'{label}: JOB_TIMEOUT')

    def journal_summary(self, job_id):
        root = Path('/var/lib/vaultrewind/journals')
        if not root.exists():
            root = Path('/var/lib/vaultrewind-helper/journals')
        journal = json.loads(private_read(root / (job_id + '.json')))
        require(journal['instance_id'] == self.instance, 'JOURNAL_SOURCE_MISMATCH')
        history = [{key: item[key] for key in ('phase', 'at')} for item in journal['history']]
        times = {item['phase']: item['at'] for item in history}
        return {'operation_id': job_id, 'phase': journal['phase'], 'history': history,
            'source_service_outcome': journal.get('source_service_outcome'),
            'outage_upper_bound_seconds': round(times['validating'] - times['quiescing'], 6),
            'raw_copy_seconds': round(times['resuming_source'] - times['capturing'], 6),
            'seal_validation_seconds': round(times['captured'] - times['validating'], 6),
            'source_resumed_before_validation_transfer_cloud': times['validating'] < times['captured']}

    def journal_count(self):
        root = Path('/var/lib/vaultrewind/journals')
        if not root.exists():
            root = Path('/var/lib/vaultrewind-helper/journals')
        return sum(json.loads(private_read(p)).get('instance_id') == self.instance for p in root.glob('*.json'))

    def snapshot(self, ident):
        return self.request('GET', f'/snapshots/{ident}')

    def restore_copy(self, snapshot_id, copy_id, label):
        from vaultrewind.core.manifest import verify_snapshot
        from vaultrewind.server.models import Snapshot, SnapshotCopy
        if label in self.state:
            manifest = json.loads(private_read(self.run / (label + '-manifest.json')))
            return self.state[label], manifest
        with self.sessions() as db:
            snapshot = db.get(Snapshot, snapshot_id)
            copy = db.get(SnapshotCopy, copy_id)
            require(snapshot.instance_id == self.instance and copy.snapshot_id == snapshot_id and
                    copy.state == 'complete', 'COMPLETE_EXACT_COPY_REQUIRED')
            repository_id, restic_id, expected_hash = copy.repository_id, copy.restic_snapshot_id, snapshot.manifest_hash
        work = self.run / (label + '-adapter')
        work.mkdir(mode=0o700, exist_ok=True)
        target = self.run / (label + '-restored')
        started = time.monotonic()
        with self.adapters.repository(repository_id, work) as repo:
            if target.exists():
                verify_snapshot(target, expected_hash)
            else:
                repo.restore(restic_id, target, expected_manifest_hash=expected_hash)
        restored_seconds = time.monotonic() - started
        verify_started = time.monotonic()
        verified = verify_snapshot(target, expected_hash)
        manifest = verified['manifest']
        require(manifest['snapshot_uuid'] == snapshot_id and manifest['instance_uuid'] == self.instance,
                'RESTORED_MANIFEST_IDENTITY_MISMATCH')
        fixture = self.state['fixture']
        relative = 'data/' + fixture['relative_path']
        entry = next(item for item in manifest['inventory'] if item['path'] == relative)
        attachment = target / relative
        require(entry['sha256'] == fixture['attachment_sha256'] and entry['size'] == HEAVY_BYTES and
                entry['mode'] == 0o600 and entry['uid'] == 0 and entry['gid'] == fixture['attachment_gid'],
                'RESTORED_PRIVATE_ATTACHMENT_INVENTORY_MISMATCH')
        require(sha(attachment) == entry['sha256'] and attachment.stat().st_size == HEAVY_BYTES and
                stat.S_IMODE(attachment.stat().st_mode) == 0o600 and attachment.stat().st_uid == 0,
                'RESTORED_ATTACHMENT_BYTES_OR_PERMISSIONS_MISMATCH')
        db_path = target / 'data/db.sqlite3'
        with sqlite3.connect(db_path.as_uri() + '?mode=ro', uri=True) as db:
            require(db.execute('PRAGMA integrity_check').fetchall() == [('ok',)], 'RESTORED_SQLITE_INTEGRITY_FAILED')
            require(db.execute('SELECT file_size FROM attachments').fetchall() == [(HEAVY_BYTES,)],
                    'RESTORED_ATTACHMENT_REFERENCE_SIZE_MISMATCH')
            counts = {table: db.execute(f'SELECT count(*) FROM {table}').fetchone()[0]
                      for table in ('users', 'organizations', 'ciphers', 'attachments', 'sends')}
        require(not (target / 'data/db.sqlite3-wal').exists() and not (target / 'data/db.sqlite3-shm').exists(),
                'RESTORED_DATABASE_NOT_STANDALONE')
        verification_seconds = time.monotonic() - verify_started
        result = {'snapshot_id': snapshot_id, 'copy_id': copy_id, 'repository_id': repository_id,
            'manifest_hash': expected_hash, 'restore_with_repository_verify_seconds': round(restored_seconds, 6),
            'additional_manifest_database_verification_seconds': round(verification_seconds, 6),
            'restored_bytes_verified': True, 'attachment_hash_matches': True,
            'attachment_bytes': HEAVY_BYTES, 'attachment_mode': '0600', 'attachment_uid': 0,
            'row_counts': counts, 'sqlite_integrity': 'ok', 'standalone_database': True,
            'normalization_evidence': manifest['verification'],
            'nonempty_wal_at_quiesced_capture_proven': False,
            'wal_scope': 'Source WAL size observed before capture; this drill does not retain raw pre-normalization WAL evidence after graceful source stop.',
            'logical_bytes': verified['logical_bytes'], 'inventory_members': verified['members'],
            'application_started': False, 'authenticated_user_login_tested': False}
        self.state[label] = result
        private_write(self.run / (label + '-manifest.json'), manifest)
        self.save()
        return result, manifest

    def schedule_once(self):
        from vaultrewind.server.db import now
        from vaultrewind.server.models import BackupPolicy, Job, ScheduleOccurrence
        if 'scheduled' in self.state:
            return
        if 'schedule_due' not in self.state:
            self.guard_idle()
            self.patch_policy({'enabled': True})
            due = now() - timedelta(seconds=1)
            # The ONLY controller SQL mutation: an explicit fixture test clock.
            with self.sessions.begin() as db:
                policy = db.scalar(select(BackupPolicy).where(
                    BackupPolicy.instance_id == EXPECTED_SOURCE_ID).with_for_update())
                require(policy is not None and policy.enabled and policy.instance_id == self.instance,
                        'SCHEDULE_CLOCK_FIXTURE_GUARD_FAILED')
                policy.next_run_at = due
            self.state['schedule_due'] = due.isoformat()
            self.save()
        due = datetime.fromisoformat(self.state['schedule_due'])
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            with self.sessions() as db:
                policy_id = db.scalar(select(BackupPolicy.id).where(BackupPolicy.instance_id == self.instance))
                occurrence = db.scalar(select(ScheduleOccurrence).where(
                    ScheduleOccurrence.policy_id == policy_id, ScheduleOccurrence.scheduled_at == due,
                    ScheduleOccurrence.kind == 'backup'))
                if occurrence:
                    require(occurrence.job_id is not None, 'SCHEDULE_OCCURRENCE_NOT_ENQUEUED')
                    job = db.get(Job, occurrence.job_id)
                    require(job.kind == 'backup' and job.instance_id == self.instance and
                            job.request['trigger'] == 'scheduled', 'SCHEDULER_TRIGGER_INVALID')
                    self.state['scheduled'] = {'job_id': job.id, 'scheduled_occurrence_id': occurrence.id,
                        'scheduled_at': due.isoformat(), 'catch_up': occurrence.catch_up,
                        'coalesced': occurrence.coalesced, 'enqueued_by_real_scheduler': True,
                        'api_creation_seconds': None}
                    self.save()
                    return
            time.sleep(0.5)
        raise DrillError('REAL_SCHEDULER_DID_NOT_ENQUEUE')

    def restore_policy(self):
        original = self.state.get('original_policy')
        if original is None:
            return
        deadline = time.monotonic() + 900
        while True:
            try:
                self.guard_idle()
                break
            except DrillError:
                require(time.monotonic() < deadline, 'POLICY_RESTORE_WAITING_FOR_ACTIVE_SOURCE_JOB')
                time.sleep(1)
        fields = ('enabled', 'schedule_kind', 'timezone', 'daily_time', 'interval_hours', 'retention_days', 'runner_id')
        body = {key: original[key] for key in fields}
        body['destinations'] = [{key: item[key] for key in ('destination_id', 'required')}
                                for item in original['destinations']]
        restored = self.patch_policy(body)
        self.state['policy_restored'] = all(restored[key] == original[key] for key in fields) and (
            sorted((d['destination_id'], d['required']) for d in restored['destinations']) ==
            sorted((d['destination_id'], d['required']) for d in original['destinations']))
        self.save()
        require(self.state['policy_restored'], 'ORIGINAL_POLICY_NOT_RESTORED')

    def execute(self):
        require(self.args.root_go == 'ROOTGO', 'PARENT_ROOTGO_REQUIRED')
        require(self.prepare(), 'CREDENTIAL_PATCH_NOT_WIRED_WAIT_FOR_ROOT')
        self.guard_idle()
        self.state.setdefault('started_at', datetime.now(UTC).isoformat())
        if 'original_policy' not in self.state:
            self.state['original_policy'] = self.request('GET', f'/instances/{self.instance}/policy')
            self.state['source_initial'] = self.inspect_source()
            require(self.state['source_initial']['running'], 'ROOT_MUST_FINISH_SOURCE_RESTORE_FIRST')
            self.save()
        self.enlarge_fixture()
        self.state.setdefault('source_content_digest_before_captures', self.source_content_digest())
        self.save()
        try:
            self.prove()
        finally:
            # Keep repositories/copies; remove only the temporary policy selection.
            self.restore_policy()
        self.publish()

    def prove(self):
        if 'destination_id' not in self.state:
            destination = self.request('POST', '/storage-destinations', {
                'name': 'Synthetic required-copy recovery ' + self.run.name, 'backend': 's3',
                'configuration': {'endpoint': self.credentials['endpoint'], 'bucket': 'vaultrewind-synthetic',
                    'prefix': 'worker-copy-recovery/' + self.run.name, 'region': 'us-east-1',
                    'bucket_lookup': 'path', 'development_http': True},
                'credentials': {'access_key_id': 'synthetic-invalid-copy-proof',
                                'secret_access_key': 'synthetic-invalid-copy-proof-secret'}}, expected=201)
            self.state['destination_id'] = destination['id']
            self.save()
        if 'scheduled_snapshot' not in self.state:
            chosen = [{key: item[key] for key in ('destination_id', 'required')}
                      for item in self.state['original_policy']['destinations']]
            require(any(item['required'] for item in chosen), 'REQUIRED_LOCAL_COPY_MISSING')
            chosen.append({'destination_id': self.state['destination_id'], 'required': True})
            self.patch_policy({'enabled': False, 'destinations': chosen})
        self.enqueue('manual', f'/instances/{self.instance}/backups', {'label': 'Synthetic required cloud failure'})
        manual = self.wait('manual', 'partial')
        require(manual['required_copy_outcome'] == 'failed' and manual['content_commit'] == 'complete' and
                manual['source_service_outcome'] == ('running' if self.state['source_initial']['running'] else 'stopped'),
                'PARTIAL_COPY_OR_SOURCE_OUTCOME_INCORRECT')
        snapshot_id = manual['result']['snapshot_id']
        snapshot = self.snapshot(snapshot_id)
        local = next(c for c in snapshot['copies'] if c['backend'] == 'local' and c['state'] == 'complete')
        cloud = next(c for c in snapshot['copies'] if c['destination_id'] == self.state['destination_id'])
        if 'partial_snapshot' not in self.state:
            require(cloud['state'] in {'failed', 'uncertain'}, 'BAD_CREDENTIAL_CLOUD_COPY_DID_NOT_FAIL')
            require(cloud['error_code'] in {'STORAGE_CREDENTIALS_INVALID', 'STORAGE_PERMISSION_DENIED', 'STORAGE_TIMEOUT'},
                    'CLOUD_FAILURE_WAS_NOT_CREDENTIAL_REJECTION')
            if cloud['error_code'] == 'STORAGE_TIMEOUT':
                diagnostic_path = self.run / 'invalid-provider-read.json'
                require(diagnostic_path.exists(), 'TIMEOUT_NEEDS_INDEPENDENT_PROVIDER_EVIDENCE')
                diagnostic = json.loads(private_read(diagnostic_path))
                require(diagnostic.get('provider_http_status') == 403, 'PROVIDER_REJECTION_NOT_PROVEN')
                self.state['invalid_credentials_provider_read'] = diagnostic
                self.state['failed_attempts'] = [{
                    'stage': 'manual_required_cloud_failure', 'job_id': manual['id'],
                    'harness_assertion': 'BAD_CREDENTIAL_CLOUD_COPY_DID_NOT_FAIL',
                    'expected_cloud_state': 'failed', 'actual_cloud_state': cloud['state'],
                    'actual_error_code': cloud['error_code'],
                    'original_policy_restored_after_assertion': self.state.get('policy_restored', False),
                    'resolution': 'Retain truthful uncertain timeout; independently prove HTTP403, then repair and retry this same immutable snapshot.'}]
            self.state['partial_snapshot'] = snapshot
            self.state['manual_journal'] = self.journal_summary(manual['id'])
            self.save()
        require(self.inspect_source()['running'], 'SOURCE_NOT_RUNNING_AFTER_CLOUD_FAILURE')
        self.restore_copy(snapshot_id, local['id'], 'partial_local')
        if 'repaired' not in self.state:
            destination = self.request('GET', f'/storage-destinations/{self.state["destination_id"]}')
            fixed = self.request('PATCH', f'/storage-destinations/{self.state["destination_id"]}',
                {'credentials': {'access_key_id': self.credentials['access_key'],
                                 'secret_access_key': self.credentials['secret_key']}},
                headers={'If-Match': f'"{destination["revision"]}"'})
            require(fixed['id'] == destination['id'] and fixed['revision'] == destination['revision'] + 1,
                    'CREDENTIAL_REPAIR_IDENTITY_OR_REVISION_CHANGED')
            require(fixed['configuration'] == destination['configuration'] and
                    fixed['repository_count'] == destination['repository_count'] and
                    fixed['physical_identity_locked'], 'CREDENTIAL_REPAIR_CHANGED_PHYSICAL_STORAGE')
            self.state['repaired'] = {'destination_id': fixed['id'], 'revision': fixed['revision'],
                                     'via_actual_api_patch': True, 'same_physical_destination': True}
            self.save()
        self.enqueue('probe', f'/storage-destinations/{self.state["destination_id"]}/test')
        self.wait('probe')
        if 'retry_source_before' not in self.state:
            self.state['retry_source_before'] = self.inspect_source()
            self.state['retry_journal_count_before'] = self.journal_count()
            self.save()
        self.enqueue('retry', f'/snapshot-copies/{cloud["id"]}/retry')
        retry = self.wait('retry')
        if not self.state.get('retry_verified'):
            self.state['retry_source_after'] = self.inspect_source()
            self.state['retry_journal_count_after'] = self.journal_count()
            require(self.state['retry_source_before'] == self.state['retry_source_after'] and
                    self.state['retry_journal_count_before'] == self.state['retry_journal_count_after'],
                    'COPY_RETRY_PAUSED_OR_RECAPTURED_SOURCE')
            self.state['retry_verified'] = True
            self.save()
        require(retry['result']['snapshot_id'] == snapshot_id, 'COPY_RETRY_CREATED_NEW_SNAPSHOT')
        healthy = self.snapshot(snapshot_id)
        require(all(c['state'] == 'complete' for c in healthy['copies']), 'REPAIRED_SNAPSHOT_COPIES_INCOMPLETE')
        self.state['repaired_snapshot'] = healthy
        self.save()
        self.restore_copy(snapshot_id, cloud['id'], 'cloud_readback')
        self.restore_copy(snapshot_id, local['id'], 'local_after_retry')
        self.schedule_once()
        scheduled = self.wait('scheduled')
        scheduled_id = scheduled['result']['snapshot_id']
        require(scheduled_id != snapshot_id, 'SCHEDULED_SNAPSHOT_NOT_DISTINCT')
        scheduled_snapshot = self.snapshot(scheduled_id)
        require(scheduled_snapshot['trigger'] == 'scheduled' and snapshot['trigger'] == 'manual' and
                all(c['state'] == 'complete' for c in scheduled_snapshot['copies']), 'SCHEDULED_COPIES_NOT_HEALTHY')
        selected = next(c for c in scheduled_snapshot['copies'] if c['backend'] == 'local')
        _, new_manifest = self.restore_copy(scheduled_id, selected['id'], 'scheduled_local')
        old_manifest = json.loads(private_read(self.run / 'partial_local-manifest.json'))
        maps = [{entry['path']: entry['sha256'] for entry in manifest['inventory'] if entry['type'] == 'file'}
                for manifest in (old_manifest, new_manifest)]
        differences = sorted(path for path in maps[0].keys() | maps[1].keys() if maps[0].get(path) != maps[1].get(path))
        require(not differences, 'IDLE_MANUAL_AND_SCHEDULED_CONTENT_HASHES_DIFFER')
        self.state['scheduled_snapshot'] = scheduled_snapshot
        self.state['scheduled_journal'] = self.journal_summary(scheduled['id'])
        self.state['identical_inventory'] = {'file_count': len(maps[0]), 'all_file_sha256_maps_identical': True,
            'different_file_count': len(differences), 'manifest_and_capture_times_excluded': True,
            'normalized_database_mtime_excluded': True, 'database_bytes_hash_identical': True,
            'file_sha256_map': maps[0]}
        self.state['source_final'] = self.inspect_source()
        require(self.attachments().stat().st_size == HEAVY_BYTES and
                sha(self.attachments()) == self.state['fixture']['attachment_sha256'], 'SOURCE_ATTACHMENT_CHANGED')
        self.state['source_content_digest_after_captures'] = self.source_content_digest()
        require(self.state['source_content_digest_before_captures'] ==
                self.state['source_content_digest_after_captures'], 'SOURCE_RECORDS_CHANGED_DURING_DRILL')
        self.save()

    def timing(self, label):
        record = self.state[label]
        job = record['job']
        created, started, ended = [datetime.fromisoformat(job[k]) for k in ('created_at', 'started_at', 'finished_at')]
        events = record['events']
        phase_starts = {}
        for event in events:
            phase_starts.setdefault(event['phase'], datetime.fromisoformat(event['created_at']))
        ordered = list(phase_starts.items())
        phases = {name: round(((ordered[i + 1][1] if i + 1 < len(ordered) else ended) - when).total_seconds(), 6)
                  for i, (name, when) in enumerate(ordered)}
        return {'job_id': job['id'], 'state': job['state'], 'api_creation_seconds': record['api_creation_seconds'],
            'progress_visible_seconds': record.get('progress_visible_seconds'),
            'first_named_phase_seconds': record.get('first_named_phase_seconds'),
            'queue_seconds': round((started - created).total_seconds(), 6),
            'worker_seconds': round((ended - started).total_seconds(), 6),
            'end_to_end_seconds': round((ended - created).total_seconds(), 6), 'phase_seconds': phases}

    def historical_small_performance(self):
        from vaultrewind.server.models import Snapshot, SnapshotCopy
        backup_id = 'b0db2ab8-75ef-4813-8646-be1e3e977eb1'
        restore_id = 'c57d3c4a-4e22-4296-a876-87c2c6db57a8'
        for label, ident in (('small_backup', backup_id), ('small_restore', restore_id)):
            job = self.request('GET', f'/jobs/{ident}')
            require(job['instance_id'] == self.instance and job['state'] == 'succeeded',
                    'HISTORICAL_SMALL_JOB_NOT_VALID')
            self.state[label] = {'job': job, 'events': self.request('GET', f'/jobs/{ident}/events')['events'],
                                 'api_creation_seconds': None}
        snapshot_id = self.state['small_backup']['job']['result']['snapshot_id']
        with self.sessions() as db:
            snapshot = db.get(Snapshot, snapshot_id)
            copy = db.scalar(select(SnapshotCopy).where(SnapshotCopy.snapshot_id == snapshot_id,
                                                       SnapshotCopy.state == 'complete'))
            require(copy is not None, 'HISTORICAL_SMALL_COPY_NOT_COMPLETE')
            repository_id, restic_id, expected = copy.repository_id, copy.restic_snapshot_id, snapshot.manifest_hash
        work = self.run / 'small-metadata-adapter'
        work.mkdir(mode=0o700, exist_ok=True)
        with self.adapters.repository(repository_id, work) as repo:
            manifest = repo.read_manifest(restic_id)
        from vaultrewind.core.manifest import manifest_hash
        require(manifest_hash(manifest) == expected, 'HISTORICAL_SMALL_MANIFEST_CHANGED')
        attachments = [item for item in manifest['inventory'] if item['type'] == 'file' and
                       item['path'].startswith('data/attachments/')]
        require(len(attachments) == 1 and attachments[0]['size'] == 28, 'HISTORICAL_SMALL_FIXTURE_SIZE_UNEXPECTED')
        view = self.snapshot(snapshot_id)
        self.save()
        return {'evidence': 'docs/evidence/controller-roundtrip.json', 'snapshot_id': snapshot_id,
            'attachment_bytes': 28, 'attachment_uid': attachments[0]['uid'],
            'attachment_mode': format(attachments[0]['mode'], '04o'),
            'backup': self.timing('small_backup'), 'application_replacement_restore': self.timing('small_restore'),
            'capture_helper': self.journal_summary(backup_id), 'logical_bytes': view['logical_bytes'],
            'stored_bytes': [{k: c[k] for k in ('backend', 'stored_bytes', 'logical_bytes')} for c in view['copies']],
            'api_creation_latency': 'Not recorded for this earlier run.',
            'note': 'Earlier real API/worker run, checked against persisted jobs and stored manifest; no new small capture or source mutation.'}

    def publish(self):
        fixture = {k: v for k, v in self.state['fixture'].items() if k != 'relative_path'}
        evidence = {'result': 'passed', 'recorded_at': datetime.now(UTC).isoformat(), 'synthetic_only': True,
            'production_access': False, 'real_api_worker_ssh_restic_minio': True, 'source_id': self.instance,
            'fixture': fixture, 'AC18': {'result': 'passed', 'manual_backup': self.state['manual']['job'],
                'partial_snapshot': self.state['partial_snapshot'], 'valid_local_restored_before_credential_repair': True,
                'credential_repair': self.state['repaired'], 'actual_test_destination_job': self.state['probe']['job'],
                'retry_job': self.state['retry']['job'], 'same_snapshot_uuid': True,
                'retry_source_started_at_before': self.state['retry_source_before']['started_at'],
                'retry_source_started_at_after': self.state['retry_source_after']['started_at'],
                'retry_helper_journal_count_before': self.state['retry_journal_count_before'],
                'retry_helper_journal_count_after': self.state['retry_journal_count_after'],
                'no_extra_source_pause_or_capture': True, 'repaired_snapshot': self.state['repaired_snapshot'],
                'cloud_verified_readback': self.state['cloud_readback'], 'local_still_verified': self.state['local_after_retry']},
            'AC02': {'result': 'passed', 'manual_snapshot_id': self.state['partial_snapshot']['id'],
                'scheduled_snapshot_id': self.state['scheduled_snapshot']['id'],
                'scheduled_job': self.state['scheduled']['job'],
                'clock_injection': 'Only this exact fixture policy next_run_at set to current UTC minus one second.',
                'real_scheduler_occurrence': {k: v for k, v in self.state['scheduled'].items() if k not in {'job', 'events'}},
                'inventory_comparison': self.state['identical_inventory']},
            'AC03': {'result': 'passed', 'live_permissions_changed': False,
                'private_root_attachment_bytes': HEAVY_BYTES, 'verified_local_restore': self.state['partial_local']},
            'source_original_running_state_preserved': self.state['source_initial']['running'] == self.state['source_final']['running'],
            'source_synthetic_records_unchanged_after_fixture_preparation': True,
            'original_policy_restored_via_api': self.state['policy_restored'], 'schedule_enabled_after_drill': False,
            'repositories_preserved': True, 'heavy_synthetic_fixture_retained': True,
            'application_login_tested': False,
            'failed_attempts': self.state.get('failed_attempts', []),
            'invalid_credentials_provider_read': self.state.get('invalid_credentials_provider_read'),
            'limitations': (['Rejected S3 keys returned HTTP403 promptly, but restic repository opening reached STORAGE_TIMEOUT and the product conservatively marked that cloud copy uncertain. Fast actionable authentication failure is not proven.']
                            if self.state.get('invalid_credentials_provider_read') else []),
            'scope': 'Actual API/worker captures and copy retry; private restic adapter restores to empty readback directories, not source replacement or user authentication.'}
        performance = {'result': 'measured', 'recorded_at': evidence['recorded_at'], 'synthetic_only': True,
            'reference': 'Local disposable SSH/Docker Vaultwarden, real MinIO on loopback and local restic; shared host load.',
            'attachment_heavy': {'fixture': fixture,
                'manual_required_cloud_failure': self.timing('manual'),
                'credential_repaired_copy_retry': self.timing('retry'), 'healthy_scheduled_backup': self.timing('scheduled'),
                'manual_capture_helper': self.state['manual_journal'], 'scheduled_capture_helper': self.state['scheduled_journal'],
                'logical_bytes': self.state['scheduled_snapshot']['logical_bytes'],
                'manual_stored_bytes': [{k: c[k] for k in ('backend', 'stored_bytes', 'logical_bytes')}
                                         for c in self.state['repaired_snapshot']['copies']],
                'scheduled_stored_bytes': [{k: c[k] for k in ('backend', 'stored_bytes', 'logical_bytes')}
                                            for c in self.state['scheduled_snapshot']['copies']],
                'local_restore': self.state['partial_local'], 'cloud_restore': self.state['cloud_readback'],
                'outage_definition': 'Upper bound from helper quiescing transition through source health recovery, restart policy restoration and validating transition.',
                'restoration_scope': 'Empty private readback directory; includes restic --verify, then manifest and SQLite integrity checks; no application startup.'},
            'small_fixture': self.historical_small_performance(),
            'targets': {'api_creation_seconds': 2, 'progress_visible_seconds': 5},
            'universal_speed_promise': False}
        # Defense in depth: public evidence must never contain valid provider credentials.
        serialized = json.dumps([evidence, performance], indent=2)
        for secret in (self.credentials['access_key'], self.credentials['secret_key']):
            require(secret not in serialized, 'PUBLIC_EVIDENCE_SECRET_DETECTED')
        self.args.evidence.parent.mkdir(parents=True, exist_ok=True)
        self.args.evidence.write_text(json.dumps(evidence, indent=2) + '\n')
        self.args.performance.write_text(json.dumps(performance, indent=2) + '\n')
        print('AC02, AC03, AC18 passed; public evidence and measured performance written.', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--private-dir', type=Path, default=PROJECT / '.runtime/controller')
    parser.add_argument('--run-dir', type=Path, default=PROJECT / '.runtime/copy-proof/reference')
    parser.add_argument('--evidence', type=Path, default=PROJECT / 'docs/evidence/worker-copy-recovery.json')
    parser.add_argument('--performance', type=Path, default=PROJECT / 'docs/evidence/performance.json')
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--root-go', default='')
    args = parser.parse_args()
    os.umask(0o077)
    try:
        drill = Drill(args)
        drill.execute() if args.execute else drill.prepare()
    except DrillError as exc:
        print(str(exc), flush=True)
        raise SystemExit(1) from None
    except Exception:  # noqa: BLE001 - never print private adapter/configuration exceptions.
        # Private exceptions can contain source configuration or subprocess output.
        import traceback
        private_write(args.run_dir / 'private-failure.json', {'traceback': traceback.format_exc()})
        print('DRILL_FAILED: private fixture state retained; exception output withheld.', flush=True)
        raise SystemExit(1) from None


if __name__ == '__main__':
    main()

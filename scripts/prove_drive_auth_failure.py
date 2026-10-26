#!/usr/bin/env python3
"""Pure preparation by default; ROOT alone releases the actual-worker auth drill.

This script never edits OAuth credentials or calls Google's OAuth API. The
recovery harness owns revocation; the owner reconnects through the private UI.
"""
from __future__ import annotations

import argparse
import copy
import json
import os
import re
import stat
import sys
import time
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.prove_drive_recovery import (
    ACTIVE,
    ALTERNATE_ID,
    CONTROLLER,
    ORIGIN,
    PRIVATE,
    PROJECT,
    SOURCE,
    SOURCE_ID,
    TERMINAL,
    DrillError,
    digest,
    guard_credential_state,
    identifier,
    policy_body,
    private_write,
    require,
    submission_action,
)
from scripts.prove_drive_recovery import (
    private_read as recovery_private_read,
)
from scripts.prove_drive_recovery import (
    validate_checkpoint as validate_recovery_checkpoint,
)

RELEASE = 'ROOTGO_AUTH_FAULT'
CREDENTIAL_STATE = CONTROLLER / 'provider-credentials'
JOURNALS = Path('/var/lib/vaultrewind-helper/journals')
SCHEDULES = ('next_run_at', 'next_verify_at', 'next_test_at')
JOB_FIELDS = ('id', 'kind', 'instance_id', 'state', 'phase', 'error_code', 'attempts',
              'content_commit', 'required_copy_outcome', 'source_service_outcome', 'reconcile_required')


def safe_code(error):
    value = str(error) if isinstance(error, DrillError) else getattr(error, 'code', '')
    return value if isinstance(value, str) and re.fullmatch(r'[A-Z0-9_]{1,160}', value) else 'AUTH_DRILL_FAILURE'


def progress(code, state=None):
    # No exception text, IDs, arbitrary phases, provider messages or credential values.
    value = {'code': code}
    if state in ACTIVE | TERMINAL:
        value['state'] = state
    print(json.dumps(value), flush=True)


def require_execution(args):
    require(args.execute and args.root_go == RELEASE and args.dedicated_test_account and
            args.destination_id and args.run_id and args.phase in {'fault', 'retry'},
            'AUTH_FAULT_PARKED_EXACT_ROOT_RELEASE_REQUIRED')
    identifier(args.destination_id)
    identifier(args.run_id)


def private_read(path):
    require(all(not p.is_symlink() for p in (path, *path.parents)), 'PRIVATE_PATH_SYMLINK_REJECTED')
    return recovery_private_read(path)


def validate_recovery(state, destination, run_id):
    validate_recovery_checkpoint(state, destination, run_id)
    require(bool(state), 'MATCHING_RECOVERY_CHECKPOINT_REQUIRED')
    for key in ('snapshot_id', 'drive_copy_id', 'local_copy_id'):
        identifier(state.get(key))
    require(state.get('policy_restored') and state.get('alternate_restore', {}).get('complete') and
            state.get('refresh', {}).get('real_rclone_access_token_refresh_persisted_in_encrypted_sql'),
            'ACTUAL_ROUNDTRIP_ALTERNATE_REFRESH_REQUIRED')
    local, drive = state.get('local_readback', {}), state.get('drive_readback', {})
    for record, backend, copy_id in ((local, 'local', state['local_copy_id']),
                                    (drive, 'drive', state['drive_copy_id'])):
        require(record.get('complete') and record.get('restored_bytes_verified') and
                record.get('saved_image_inventory_verified') and record.get('sqlite_integrity') == 'ok' and
                record.get('snapshot_id') == state['snapshot_id'] and record.get('copy_id') == copy_id and
                record.get('backend') == backend and re.fullmatch(r'[0-9a-f]{64}', record.get('manifest_hash', '')),
                'BOUND_COMPLETE_BASE_READBACK_REQUIRED')
    require(local['manifest_hash'] == drive['manifest_hash'] and
            local['whole_file_map_sha256'] == drive['whole_file_map_sha256'], 'BASE_LOCAL_DRIVE_BYTES_DIFFER')
    revocation = state.get('revocation', {})
    require(revocation.get('locally_invalidated') and revocation.get('google_revoke_acknowledged') and
            revocation.get('actual_google_refresh_error') == 'STORAGE_AUTH_EXPIRED' and
            revocation.get('source_unchanged_and_local_copy_verified') and
            re.fullmatch(r'[0-9a-f]{64}', revocation.get('old_grant_sha256', '')),
            'RECOVERY_REAL_GOOGLE_REVOCATION_PROOF_REQUIRED')
    return {'snapshot_id': state['snapshot_id'], 'local_copy_id': state['local_copy_id'],
            'drive_copy_id': state['drive_copy_id'], 'manifest_hash': local['manifest_hash'],
            'whole_file_map_sha256': local['whole_file_map_sha256'],
            'configuration_sha256': state['configuration_sha256'],
            'old_grant_sha256': revocation['old_grant_sha256']}


def validate_retention(value, binding, destination, run_id):
    require(value.get('run_id') == run_id and value.get('destination_id') == destination and
            value.get('result') == 'live_retention_proven' and value.get('retention_live_proven') and
            value.get('input_snapshot_id') == binding['snapshot_id'] and
            value.get('input_manifest_hash') == binding['manifest_hash'] and
            value.get('configuration_sha256') == binding['configuration_sha256'] and
            len(value.get('rounds', [])) == 2 and all(r.get('complete') for r in value['rounds']),
            'MATCHING_COMPLETED_LIVE_RETENTION_REQUIRED')


def validate_state(state, binding, destination, run_id):
    require(state.get('version') == 1 and state.get('source_id') == SOURCE_ID and
            state.get('destination_id') == destination and state.get('run_id') == run_id and
            state.get('base') == binding and isinstance(state.get('steps'), dict) and
            isinstance(state.get('failures'), list), 'AUTH_CHECKPOINT_BINDING_MISMATCH')
    require(set(state['steps']) <= {'fault', 'retry'}, 'AUTH_CHECKPOINT_UNKNOWN_STEP')
    for stage, record in state['steps'].items():
        require(record.get('idempotency_key') == f'drive-auth:{run_id}:{stage}', 'STABLE_IDENTITY_CHANGED')
        if record.get('job_id'):
            identifier(record['job_id'])
    for key in ('snapshot_id', 'local_copy_id', 'drive_copy_id', 'drive_repository_id'):
        if key in state:
            identifier(state[key])
    return state


def bind_source_configuration(state, binding):
    """Add generation only to the legacy, failed, wholly unissued preflight."""
    previous = state.get('source_configuration')
    if not previous or previous == binding:
        return copy.deepcopy(binding)
    legacy_fields = {'revision', 'fingerprint', 'physical_identity', 'container_id'}
    require(set(previous) == legacy_fields and set(binding) == legacy_fields | {'active_generation'} and
            all(previous[k] == binding[k] for k in legacy_fields), 'SOURCE_CONFIGURATION_CHANGED')
    forbidden = {'policy_mutation_intent', 'policy_restore_attempted', 'original_policy', 'installed_policy',
                 'installed_policy_revision', 'source_before_fault', 'source_after_fault', 'source_before_retry',
                 'snapshot_id', 'local_copy_id', 'drive_copy_id', 'drive_repository_id', 'fault_proven', 'retry_proven'}
    require(not state.get('steps') and not forbidden.intersection(state) and
            state.get('retry_attempts', []) == [] and
            state.get('failures') and all(e.get('phase') == 'fault' and
                e.get('code') == 'EXACT_RUNNING_SYNTHETIC_SOURCE_REQUIRED' for e in state['failures']) and
            set(state.get('readbacks', {})) == {'base_before_fault'} and binding['active_generation'],
            'SOURCE_GENERATION_MIGRATION_REQUIRES_UNISSUED_PREFLIGHT')
    identifier(binding['active_generation'])
    proof, base = state['readbacks']['base_before_fault'], state['base']
    require(proof.get('complete') is True and proof.get('restored_bytes_verified') is True and
            proof.get('saved_image_inventory_verified') is True and proof.get('sqlite_integrity') == 'ok' and
            proof.get('backend') == 'local' and proof.get('snapshot_id') == base['snapshot_id'] and
            proof.get('copy_id') == base['local_copy_id'] and proof.get('manifest_hash') == base['manifest_hash'] and
            proof.get('whole_file_map_sha256') == base['whole_file_map_sha256'],
            'SOURCE_GENERATION_MIGRATION_REQUIRES_BOUND_LOCAL_READBACK')
    # No resets: the caller persists exactly the old fields plus the catalog generation.
    return {**previous, 'active_generation': binding['active_generation']}


def validate_source_descriptor(descriptor, configuration, restore_job=None, restore_journal=None):
    """Pure Docker + catalog + current helper-fence proof; enrollment IDs are historical."""
    labels = descriptor.get('Config', {}).get('Labels') or {}
    mounts = [m for m in descriptor.get('Mounts', []) if m.get('Destination') == '/data']
    require(descriptor.get('Name') == '/vr-ssh-source' and
            labels.get('org.vaultrewind.instance') == SOURCE_ID and len(mounts) == 1 and
            mounts[0].get('Type') == 'bind' and mounts[0].get('Source') == str(SOURCE) and
            descriptor.get('State', {}).get('Running') is True and
            re.fullmatch(r'[0-9a-f]{64}', descriptor.get('Id', '')),
            'EXACT_RUNNING_SYNTHETIC_SOURCE_REQUIRED')
    generation = configuration['active_generation']
    if generation is None:
        require(descriptor['Id'] == configuration['container_id'] and
                not labels.get('org.vaultrewind.operation') and not labels.get('org.vaultrewind.role') and
                restore_job is None and restore_journal is None, 'INITIAL_SOURCE_IDENTITY_CHANGED')
        return {'active_generation': None, 'restore_fencing_token': None}
    identifier(generation)
    require(labels.get('org.vaultrewind.operation') == generation and
            labels.get('org.vaultrewind.role') == 'active', 'SOURCE_ACTIVE_GENERATION_LABEL_MISMATCH')
    job, journal = restore_job or {}, restore_journal or {}
    require(job.get('id') == generation and job.get('kind') == 'restore' and job.get('instance_id') == SOURCE_ID and
            job.get('state') == 'succeeded' and job.get('reconcile_required') is False and
            job.get('target_activation_outcome') == 'complete' and job.get('content_commit') == 'complete' and
            job.get('source_service_outcome') == 'running' and type(job.get('fencing_token')) is int and
            job['fencing_token'] > 0 and job.get('request', {}).get('target_id') == SOURCE_ID and
            job.get('result', {}).get('active_generation') == generation and
            all(job.get('result', {}).get(key) is True for key in
                ('candidate_validated', 'activation_started', 'application_started', 'restored_bytes_verified')),
            'SOURCE_SUCCEEDED_CURRENT_RESTORE_REQUIRED')
    require(journal.get('operation_id') == generation and journal.get('instance_id') == SOURCE_ID and
            journal.get('kind') == 'restore' and journal.get('phase') == 'complete' and
            journal.get('active_generation') == generation and journal.get('fencing_token') == job['fencing_token'] and
            journal.get('final_id') == descriptor['Id'] and journal.get('final_name') == 'vr-ssh-source' and
            journal.get('activation_started') is True and journal.get('watchdog_armed') is False and
            journal.get('source_service_outcome') == 'running', 'SOURCE_CURRENT_RESTORE_FENCE_UNPROVEN')
    return {'active_generation': generation, 'restore_fencing_token': job['fencing_token']}


def guard_other_runs(states, binding, destination, run_id):
    """Changing a CLI UUID cannot hide an earlier ambiguous submission or grant drill."""
    for state in states:
        if state.get('destination_id') != destination or state.get('run_id') == run_id:
            continue
        attempted = any(r.get('attempted') or r.get('job_id') for r in state.get('steps', {}).values())
        require(not attempted, 'OTHER_RUN_SUBMISSION_REQUIRES_ROOT_RECONCILIATION')
        require(state.get('base', {}).get('old_grant_sha256') != binding['old_grant_sha256'],
                'REVOKED_GRANT_ALREADY_BOUND_TO_ANOTHER_RUN')


def fault_policy(original, destination):
    require(original.get('enabled') is False and any(e['backend'] == 'local' and e['required']
            for e in original['destinations']), 'DISABLED_POLICY_REQUIRED_VALID_LOCAL_REQUIRED')
    body = policy_body(original)
    require(len({e['destination_id'] for e in body['destinations']}) == len(body['destinations']),
            'DUPLICATE_POLICY_DESTINATION')
    chosen = next((e for e in body['destinations'] if e['destination_id'] == destination), None)
    if chosen is None:
        body['destinations'].append({'destination_id': destination, 'required': True})
    else:
        chosen['required'] = True
    return body


def canonical_policy(value):
    body = policy_body(value)
    body['destinations'] = sorted(body['destinations'], key=lambda entry: entry['destination_id'])
    return body


def validate_planned_job(job, planned):
    require(job['kind'] == planned['kind'] and job['instance_id'] == SOURCE_ID and
            all(job['request'].get(k) == v for k, v in planned['request'].items() if k != 'repositories'),
            'SUBMITTED_JOB_DOES_NOT_MATCH_DURABLE_PLAN')
    if planned['kind'] == 'retry_copy':
        require(job['request'] == planned['request'], 'RETRY_MUST_USE_EXACT_FAILED_COPY_PLAN')
    else:
        expected = sorted(planned['request']['repositories'], key=lambda item: item['repository_id'])
        actual = sorted(job['request']['repositories'], key=lambda item: item['repository_id'])
        require(actual == expected, 'BACKUP_POLICY_REPOSITORIES_CHANGED')


def validate_fault(job, snapshot, destination, local_copy_id):
    require(job['kind'] == 'backup' and job['instance_id'] == SOURCE_ID and job['state'] == 'partial' and
            job['content_commit'] == 'complete' and job['source_service_outcome'] == 'running' and
            job['required_copy_outcome'] == 'failed' and not job.get('reconcile_required'),
            'ACTUAL_PARTIAL_LOCAL_COMPLETE_AUTH_FAILURE_NOT_PROVEN')
    require(snapshot['id'] == job['result']['snapshot_id'] and snapshot['instance_id'] == SOURCE_ID and
            snapshot['completeness'] == 'complete', 'FAULT_SNAPSHOT_IDENTITY_MISMATCH')
    local = [c for c in snapshot['copies'] if c['id'] == local_copy_id and c['backend'] == 'local']
    drive = [c for c in snapshot['copies'] if c['destination_id'] == destination and c['backend'] == 'drive']
    require(len(local) == len(drive) == 1 and local[0]['state'] == 'complete' and
            drive[0]['state'] == 'failed' and drive[0].get('error_code') == 'STORAGE_AUTH_EXPIRED',
            'EXACT_LOCAL_COMPLETE_DRIVE_AUTH_EXPIRED_REQUIRED')
    return drive[0]


def validate_retry(job, state, snapshot):
    require(job['kind'] == 'retry_copy' and job['state'] == 'succeeded' and job['instance_id'] == SOURCE_ID and
            job['result'].get('snapshot_id') == state['snapshot_id'] == snapshot['id'] and
            job['content_commit'] == 'complete' and not job.get('reconcile_required'),
            'SAME_SNAPSHOT_RETRY_NOT_SUCCESSFUL')
    for copy_id in (state['local_copy_id'], state['drive_copy_id']):
        matches = [c for c in snapshot['copies'] if c['id'] == copy_id]
        require(len(matches) == 1 and matches[0]['state'] == 'complete', 'BOTH_SAME_SNAPSHOT_COPIES_REQUIRED')


def compare_source(before, after, *, retry):
    fields = ('container_id', 'active_generation', 'restore_fencing_token',
              'logical_database_sha256', 'non_database_sha256', 'metadata_sha256')
    if retry:
        fields += ('started_at', 'whole_inventory_sha256', 'source_journal_count', 'source_journals_sha256')
    require(before['running'] and after['running'] and all(before[k] == after[k] for k in fields),
            'SOURCE_CHANGED_DURING_RETRY' if retry else 'SOURCE_CONTENT_CHANGED_DURING_FAULT')


@contextmanager
def execution_lock(args):
    require_execution(args)
    import fcntl

    directory = PROJECT / '.runtime/drive-auth-fault'
    require(all(not p.is_symlink() for p in (directory, *directory.parents)), 'RUNTIME_SYMLINK_REJECTED')
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(directory.stat().st_uid == os.geteuid() and not directory.stat().st_mode & 0o077,
            'PRIVATE_AUTH_RUNTIME_REQUIRED')
    fd = os.open(directory / 'execution.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o077,
                'PRIVATE_AUTH_LOCK_REQUIRED')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise DrillError('AUTH_DRILL_ALREADY_RUNNING') from None
        yield
    finally:
        os.close(fd)


class AuthFaultDrill:
    def __init__(self, args):
        require_execution(args)  # First: even importing runtime dependencies is gated.
        import httpx

        from vaultrewind.server.adapters import Adapters, SQLCredentialStore
        from vaultrewind.server.db import make_engine, sessions
        from vaultrewind.server.settings import Settings

        self.args, self.destination, self.run_id = args, args.destination_id, args.run_id
        self.parent = PROJECT / '.runtime/drive-auth-fault'
        self.root = self.parent / self.run_id
        self.recovery_path = PROJECT / '.runtime/drive-proof' / self.run_id / 'checkpoint.json'
        self.recovery = json.loads(private_read(self.recovery_path))
        binding = validate_recovery(self.recovery, self.destination, self.run_id)
        validate_retention(json.loads(private_read(PROJECT / 'docs/evidence/drive-retention.json')),
                           binding, self.destination, self.run_id)
        others = [json.loads(private_read(p)) for p in self.parent.glob('*/checkpoint.json')]
        guard_other_runs(others, binding, self.destination, self.run_id)
        require(all(not p.is_symlink() for p in (self.root, *self.root.parents)), 'RUNTIME_SYMLINK_REJECTED')
        self.root.mkdir(mode=0o700, exist_ok=True)
        require(self.root.stat().st_uid == os.geteuid() and not self.root.stat().st_mode & 0o077,
                'PRIVATE_AUTH_RUNTIME_REQUIRED')
        self.checkpoint = self.root / 'checkpoint.json'
        self.state = validate_state(json.loads(private_read(self.checkpoint)), binding, self.destination,
            self.run_id) if self.checkpoint.exists() else {
                'version': 1, 'source_id': SOURCE_ID, 'destination_id': self.destination, 'run_id': self.run_id,
                'base': binding, 'steps': {}, 'failures': [], 'readbacks': {}, 'retry_attempts': []}
        evidence = PROJECT / 'docs/evidence/drive-auth-failure.json'
        if evidence.exists():
            prior = json.loads(private_read(evidence))
            require(prior.get('run_id') == self.run_id and prior.get('destination_id') == self.destination,
                    'OTHER_AUTH_EVIDENCE_REQUIRES_ROOT_REVIEW')
        fixture = json.loads(private_read(PRIVATE / 'integration.json'))
        require(fixture['source_id'] == SOURCE_ID and fixture['alternate_id'] == ALTERNATE_ID,
                'EXACT_NATIVE_SYNTHETIC_FIXTURE_REQUIRED')
        self.settings = Settings(database_url=private_read(PRIVATE / 'database-url').decode().strip(),
            master_key_file=PRIVATE / 'master', bootstrap_secret_file=PRIVATE / 'bootstrap',
            staging_dir=CONTROLLER / 'staging', local_storage_root=CONTROLLER / 'backups',
            provider_credential_state_dir=CREDENTIAL_STATE, public_origin=ORIGIN, secure_cookies=False)
        self.engine = make_engine(self.settings.database_url)
        require(self.engine.url.get_backend_name() == 'postgresql' and
                self.engine.url.host in {None, 'localhost', '127.0.0.1'}, 'NATIVE_PRIVATE_POSTGRES_REQUIRED')
        self.sessions = sessions(self.engine)
        self.adapters = Adapters(self.settings, self.sessions)
        self.store = SQLCredentialStore(self.adapters)
        require(self.store.state_directory == CREDENTIAL_STATE, 'GLOBAL_PROVIDER_CREDENTIAL_STATE_REQUIRED')
        self.box = self.adapters.secrets.box()
        cookies = json.loads(private_read(PRIVATE / 'api-cookies.json'))
        self.secret_values = list(cookies.values())
        self.http = httpx.Client(base_url=ORIGIN, cookies=cookies, timeout=30, trust_env=False,
            follow_redirects=False, headers={'Origin': ORIGIN, 'X-CSRF-Token': cookies['vr_csrf']})
        self.save()

    def save(self):
        private_write(self.checkpoint, self.state)

    def request(self, method, path, body=None, *, expected=200, key=None, headers=None):
        require(method in {'GET', 'POST', 'PATCH'}, 'UNSUPPORTED_DRILL_METHOD')
        selected = dict(headers or {})
        if method != 'GET':
            require(bool(key), 'DURABLE_MUTATION_IDENTITY_REQUIRED')
            selected['Idempotency-Key'] = key
        response = self.http.request(method, '/api/v1' + path, json=body, headers=selected)
        if response.status_code != expected:
            # The raw response may carry private details; never serialize it.
            raise DrillError('AUTH_DRILL_HTTP_' + str(response.status_code))
        return response.json()

    def idle_source(self, allowed=()):
        from sqlalchemy import select

        from vaultrewind.server.models import Instance, Job, JobResource
        with self.sessions() as db:
            source = db.get(Instance, SOURCE_ID)
            physical = 'instance:' + source.physical_identity
            ids = set(db.scalars(select(Job.id).where(Job.instance_id == SOURCE_ID, Job.state.in_(ACTIVE))))
            ids.update(db.scalars(select(Job.id).join(JobResource).where(
                JobResource.resource_key == physical, Job.state.in_(ACTIVE))))
            require(not ids - set(allowed), 'ACTIVE_SOURCE_JOB_REQUIRES_RECONCILIATION')

    def credential_quiet(self):
        """Inspect only: no lease inserts, force-unlocks, OAuth calls or pending recovery."""
        from sqlalchemy import select

        from vaultrewind.server.models import Job, JobResource, ResourceLease
        require(all(not p.is_symlink() for p in (CREDENTIAL_STATE, *CREDENTIAL_STATE.parents)),
                'CREDENTIAL_STATE_DIRECTORY_UNSAFE')
        require(CREDENTIAL_STATE.is_dir(), 'EXISTING_GLOBAL_PROVIDER_CREDENTIAL_STATE_REQUIRED')
        for child in (CREDENTIAL_STATE, CREDENTIAL_STATE / 'pending', CREDENTIAL_STATE / 'sessions'):
            if child.exists() or child.is_symlink():
                require(child.is_dir() and not child.is_symlink() and child.stat().st_uid == os.geteuid() and
                        not child.stat().st_mode & 0o077, 'CREDENTIAL_STATE_DIRECTORY_UNSAFE')
        pending = list((CREDENTIAL_STATE / 'pending').glob(self.destination + '.*.pending-credential'))
        registered = list((CREDENTIAL_STATE / 'sessions').glob(self.destination + '.*.drive-session'))
        with self.sessions() as db:
            lease = db.scalar(select(ResourceLease).where(
                ResourceLease.resource_key == 'credential:' + self.destination))
            active = db.scalar(select(Job.id).join(JobResource).where(
                JobResource.resource_key == 'credential:' + self.destination, Job.state.in_(ACTIVE)))
            guard_credential_state(len(pending), len(registered),
                                   bool(active or (lease and lease.owner_job_id)))

    def credential(self, *, revoked):
        from vaultrewind.storage.credentials import credential_context
        stored = self.store.load(self.destination)
        require(stored is not None, 'EXISTING_SQL_DRIVE_GRANT_REQUIRED')
        value = self.box.decrypt(stored.envelope, context=credential_context(self.destination))
        self.secret_values.extend(str(value[k]) for k in ('client_id', 'client_secret') if value.get(k))
        self.secret_values.extend(str(v) for k, v in value.get('token', {}).items()
                                  if k in {'access_token', 'refresh_token'} and v)
        require(value.get('type') == 'google_drive_oauth' and value.get('scope') == 'drive.file' and
                value.get('grant_id'), 'DEDICATED_MY_DRIVE_GRANT_REQUIRED')
        grant = {'grant_sha256': digest(value['grant_id']), 'generation': stored.generation}
        if revoked:
            require(value.get('revoked') is True and value.get('revoked_at'), 'LOCALLY_REVOKED_SQL_GRANT_REQUIRED')
            old = self.box.decrypt(self.recovery['revocation']['encrypted_old_credential'],
                                   context='drive-drill:' + self.run_id + ':old-grant')
            require(digest(old['grant_id']) == self.state['base']['old_grant_sha256'] and
                    all(value.get(k) == old.get(k) for k in
                        ('type', 'scope', 'client_id', 'client_secret', 'folder_id', 'token')),
                    'SQL_REVOKED_CREDENTIAL_NOT_BOUND_TO_RECOVERY')
            prior = self.state.get('revoked_credential')
            require(prior is None or prior == grant, 'REVOKED_SQL_GRANT_CHANGED')
        else:
            prior = self.state.get('revoked_credential', {})
            require(not value.get('revoked') and not value.get('revoked_at') and
                    value.get('token', {}).get('refresh_token') and
                    grant['grant_sha256'] not in {prior.get('grant_sha256'), self.state['base']['old_grant_sha256']},
                    'FRESH_PRIVATE_UI_RECONNECT_REQUIRED')
            require(not self.state.get('retry_grant') or self.state['retry_grant'] == grant,
                    'RETRY_GRANT_CHANGED_REQUIRES_ROOT_REVIEW')
        view = self.request('GET', '/storage-destinations/' + self.destination)
        require(view['backend'] == 'drive' and digest(view['configuration']) == self.state['base']['configuration_sha256']
                and value.get('folder_id') == view['configuration'].get('folder_id'), 'SAME_DRIVE_CONFIGURATION_REQUIRED')
        return grant

    def catalog_binding(self):
        from sqlalchemy import select

        from vaultrewind.server.models import Instance, Repository, Snapshot, SnapshotCopy, StorageDestination
        base = self.state['base']
        with self.sessions() as db:
            source = db.get(Instance, SOURCE_ID)
            require(source and not source.archived and not source.is_runner and source.readiness == 'ready',
                    'READY_EXACT_SOURCE_REQUIRED')
            binding = {'revision': source.revision, 'fingerprint': source.fingerprint,
                       'physical_identity': source.physical_identity, 'container_id': source.container_id,
                       'active_generation': source.active_generation}
            binding = bind_source_configuration(self.state, binding)
            for copy_id, backend in ((base['local_copy_id'], 'local'), (base['drive_copy_id'], 'drive')):
                point = db.get(Snapshot, base['snapshot_id'])
                item = db.get(SnapshotCopy, copy_id)
                require(point and item, 'BASE_CATALOG_POINT_REQUIRED')
                repo = db.get(Repository, item.repository_id)
                dest = db.get(StorageDestination, repo.destination_id)
                require(item.snapshot_id == point.id and point.instance_id == repo.instance_id == SOURCE_ID and
                        item.repository_id == self.recovery[backend + '_readback']['repository_id'] and
                        item.state == point.completeness == 'complete' and dest.backend == backend and
                        not dest.archived and item.manifest_hash == point.manifest_hash == base['manifest_hash'],
                        'BOUND_BASE_COMPLETE_COPIES_REQUIRED')
                if backend == 'drive':
                    require(dest.id == self.destination, 'BASE_DRIVE_DESTINATION_MISMATCH')
                else:
                    config = self.adapters.secrets.get(db, dest.configuration_secret_id)
                    require(config.get('path') == str(CONTROLLER / 'backups'), 'EXACT_NATIVE_LOCAL_ROOT_REQUIRED')
                    self.adapters.check_local({**config, '_destination_id': dest.id})
            destination = db.get(StorageDestination, self.destination)
            require(destination and not destination.archived, 'EXISTING_DRIVE_DESTINATION_REQUIRED')
            # Retention creates isolated catalogs, never foreign native registrations.
            foreign = db.scalar(select(Repository.id).where(Repository.destination_id == self.destination,
                (Repository.instance_id != SOURCE_ID) | Repository.instance_id.is_(None)))
            require(not foreign, 'DRIVE_DESTINATION_MUST_BE_DEDICATED_TO_SOURCE')
        self.state['source_configuration'] = binding
        self.save()

    def source_witness(self):
        import sqlite3
        import subprocess

        from vaultrewind.core.manifest import inventory
        from vaultrewind.server.models import Instance, Job
        require_execution(self.args)
        require(all(not p.is_symlink() for p in (SOURCE, *SOURCE.parents)), 'SOURCE_PATH_SYMLINK_REJECTED')
        response = subprocess.run(['docker', 'inspect', 'vr-ssh-source'], capture_output=True,
                                  timeout=30, check=False)
        require(response.returncode == 0, 'SOURCE_INSPECTION_FAILED')
        descriptor = json.loads(response.stdout)[0]
        configuration = self.state['source_configuration']
        generation = configuration['active_generation']
        job, journal = None, None
        with self.sessions() as db:
            source = db.get(Instance, SOURCE_ID)
            require(source and {'revision': source.revision, 'fingerprint': source.fingerprint,
                'physical_identity': source.physical_identity, 'container_id': source.container_id,
                'active_generation': source.active_generation} == configuration, 'SOURCE_CONFIGURATION_CHANGED')
            if generation is not None:
                identifier(generation)
                row = db.get(Job, generation)
                require(row is not None, 'SOURCE_SUCCEEDED_CURRENT_RESTORE_REQUIRED')
                job = {k: copy.deepcopy(getattr(row, k)) for k in (*JOB_FIELDS, 'fencing_token',
                                                                  'request', 'result', 'target_activation_outcome')}
                journal = json.loads(private_read(JOURNALS / (generation + '.json')))
        provenance = validate_source_descriptor(descriptor, configuration, job, journal)
        entries = inventory(SOURCE)
        fields = ('path', 'type', 'sha256', 'size', 'uid', 'gid', 'mode', 'link_target', 'hardlink_to', 'xattrs')
        whole = [{k: e[k] for k in fields if k in e} for e in entries]
        non_db = [e for e in whole if e['path'] not in {'db.sqlite3', 'db.sqlite3-wal', 'db.sqlite3-shm'}]
        metadata = [{k: e[k] for k in ('path', 'type', 'uid', 'gid', 'mode', 'link_target', 'hardlink_to', 'xattrs')
                     if k in e} for e in whole if e['path'] not in {'db.sqlite3-wal', 'db.sqlite3-shm'}]
        require(not (SOURCE / 'db.sqlite3').is_symlink(), 'SOURCE_DATABASE_SYMLINK_REJECTED')
        # mode=ro + query_only: WAL is read through SQLite, never immutable=1.
        with sqlite3.connect((SOURCE / 'db.sqlite3').as_uri() + '?mode=ro', uri=True) as db:
            db.execute('PRAGMA query_only=ON')
            db.execute('BEGIN')
            schema = list(db.execute("SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name"))
            logical = []
            for kind, name, _table, _sql in schema:
                if kind == 'table':
                    quoted = '"' + name.replace('"', '""') + '"'
                    rows = [[{'blob': v.hex()} if isinstance(v, bytes) else v for v in row]
                            for row in db.execute('SELECT * FROM ' + quoted)]
                    logical.append([name, sorted(rows, key=lambda row: json.dumps(row, sort_keys=True))])
            logical_hash = digest({'schema': schema, 'tables': logical})
        source_journals = []
        require(JOURNALS.is_dir() and all(not p.is_symlink() for p in (JOURNALS, *JOURNALS.parents)),
                'HELPER_JOURNAL_DIRECTORY_UNSAFE')
        for path in sorted(JOURNALS.glob('*.json')):
            value = json.loads(private_read(path))
            if value.get('instance_id') == SOURCE_ID:
                source_journals.append([path.name, digest(value)])
        return {'running': True, 'container_id': descriptor['Id'], 'started_at': descriptor['State']['StartedAt'],
                **provenance,
                'whole_inventory_sha256': digest(whole), 'logical_database_sha256': logical_hash,
                'non_database_sha256': digest(non_db), 'metadata_sha256': digest(metadata),
                'source_journal_count': len(source_journals), 'source_journals_sha256': digest(source_journals)}

    def policy(self):
        return self.request('GET', f'/instances/{SOURCE_ID}/policy')

    def patch_policy(self, current, body, stage):
        return self.request('PATCH', f'/instances/{SOURCE_ID}/policy', body,
            key=f'drive-auth:{self.run_id}:policy:{stage}', headers={'If-Match': f'"{current["revision"]}"'})

    def install_policy(self):
        self.idle_source()
        current = self.policy()
        if 'original_policy' not in self.state:
            fault_policy(current, self.destination)
            require(any(e['backend'] == 'local' and e['required'] and
                        e['repository_id'] == self.recovery['local_readback']['repository_id']
                        for e in current['destinations']), 'BASE_LOCAL_REPOSITORY_MUST_REMAIN_REQUIRED')
            require(all(current.get(k) == self.recovery['original_policy'].get(k) for k in SCHEDULES) and
                    canonical_policy(current) == canonical_policy(self.recovery['original_policy']),
                    'ORIGINAL_RECOVERY_POLICY_CHANGED')
            self.state['original_policy'] = copy.deepcopy(current)
            self.state['policy_restored'] = True
            self.save()
        original = self.state['original_policy']
        desired = fault_policy(original, self.destination)
        require(canonical_policy(current) in (canonical_policy(original), canonical_policy(desired)),
                'UNEXPECTED_POLICY_CHANGE_REQUIRES_ROOT_REVIEW')
        require(all(current.get(k) == original.get(k) for k in SCHEDULES), 'POLICY_SCHEDULE_CHANGED')
        self.state['policy_mutation_intent'] = True
        self.state['policy_restored'] = False
        self.save()  # Restore even if PATCH succeeded but its response is lost.
        if canonical_policy(current) != canonical_policy(desired):
            current = self.patch_policy(current, desired, 'install')
        require(canonical_policy(current) == canonical_policy(desired) and
                all(current.get(k) == original.get(k) for k in SCHEDULES), 'FAULT_POLICY_NOT_INSTALLED')
        self.state['installed_policy_revision'] = current['revision']
        self.state['installed_policy'] = copy.deepcopy(current)
        self.save()

    def restore_policy(self):
        if not self.state.get('policy_mutation_intent'):
            return
        self.idle_source()
        current, original = self.policy(), self.state['original_policy']
        desired = fault_policy(original, self.destination)
        require(all(current.get(k) == original.get(k) for k in SCHEDULES), 'POLICY_SCHEDULE_CHANGED')
        if canonical_policy(current) != canonical_policy(original):
            require(canonical_policy(current) == canonical_policy(desired), 'POLICY_RESTORE_CONCURRENT_CHANGE')
            require(current['revision'] == self.state.get('installed_policy_revision', original['revision'] + 1),
                    'POLICY_RESTORE_REVISION_CHANGED')
            self.state['policy_restore_attempted'] = True
            self.save()
            current = self.patch_policy(current, policy_body(original), 'restore')
        require(canonical_policy(current) == canonical_policy(original) and
                all(current.get(k) == original.get(k) for k in SCHEDULES), 'EXACT_DISABLED_POLICY_NOT_RESTORED')
        self.state['policy_restored'] = True
        self.save()

    def planned_job(self, stage):
        if stage == 'fault':
            config = self.state['source_configuration']
            policy = self.state['installed_policy']
            return {'kind': 'backup', 'request': {'configuration_revision': config['revision'],
                                                  'fingerprint': config['fingerprint'],
                                                  'label': 'Dedicated synthetic Drive auth fault',
                                                  'instance_id': SOURCE_ID, 'trigger': 'manual',
                                                  'policy_revision': policy['revision'],
                                                  'outage_seconds': policy['outage_seconds'],
                                                  'repositories': [{'repository_id': e['repository_id'],
                                                                    'required': e['required']}
                                                                   for e in policy['destinations']]}}
        return {'kind': 'retry_copy', 'request': {'snapshot_id': self.state['snapshot_id'],
            'repository_id': self.state['drive_repository_id'],
            'original_job_id': self.state['steps']['fault']['job_id']}}

    def lookup_job(self, record):
        from sqlalchemy import select

        from vaultrewind.server.models import IdempotencyRecord, Job
        with self.sessions() as db:
            ids = set(db.scalars(select(Job.id).where(Job.idempotency_key == record['idempotency_key'])))
            ids.update(db.scalars(select(IdempotencyRecord.job_id).where(
                IdempotencyRecord.key == record['idempotency_key'])))
            require(len(ids) == 1, 'SUBMISSION_RESPONSE_UNRESOLVED_DO_NOT_REPEAT')
            job_id = ids.pop()
            require(not record.get('job_id') or record['job_id'] == job_id,
                    'PERSISTED_JOB_ID_AND_IDEMPOTENCY_RECORD_DIFFER')
            job = db.get(Job, job_id)
            require(job is not None, 'PLANNED_JOB_MISSING')
            view = {k: getattr(job, k) for k in JOB_FIELDS}
            view.update(request=copy.deepcopy(job.request), result=copy.deepcopy(job.result))
            validate_planned_job(view, record['planned_job'])
            return view

    def submit(self, stage):
        planned = self.planned_job(stage)
        record = self.state['steps'].setdefault(stage, {'idempotency_key': f'drive-auth:{self.run_id}:{stage}',
                                                      'planned_job': planned})
        require(record['planned_job'] == planned, 'DURABLE_JOB_PLAN_CHANGED')
        action = submission_action(record)
        if action == 'submit_once':
            self.idle_source()
            self.credential_quiet()
            grant = self.credential(revoked=stage == 'fault')
            require(grant == self.state['revoked_credential' if stage == 'fault' else 'retry_grant'],
                    'SUBMISSION_GRANT_CHANGED')
            if stage == 'fault':
                current = self.policy()
                require(current['revision'] == self.state['installed_policy_revision'] and
                        canonical_policy(current) == canonical_policy(self.state['installed_policy']),
                        'SUBMISSION_POLICY_CHANGED')
            record['attempted'] = True
            self.save()
            path = (f'/instances/{SOURCE_ID}/backups' if stage == 'fault' else
                    '/snapshot-copies/' + self.state['drive_copy_id'] + '/retry')
            body = {'label': planned['request']['label']} if stage == 'fault' else {}
            response = self.request('POST', path, body, expected=202, key=record['idempotency_key'])
            record['job_id'] = identifier(response['job_id'])
            self.save()
        # Reconcile even a returned ID against the durable plan and SQL idempotency record.
        job = self.lookup_job(record)
        record['job_id'] = job['id']
        self.save()
        return job['id']

    def wait(self, stage, timeout=1800):
        record = self.state['steps'][stage]
        deadline, last = time.monotonic() + timeout, None
        while time.monotonic() < deadline:
            job = self.lookup_job(record)
            if job['state'] != last:
                progress('AUTH_' + stage.upper() + '_JOB', job['state'])
                last = job['state']
            if job['state'] in TERMINAL:
                record['job'] = {k: job[k] for k in JOB_FIELDS}
                record['result'] = {'snapshot_id': job['result'].get('snapshot_id')}
                record['terminal_observation'] = copy.deepcopy(record['job'])
                self.save()
                return job
            time.sleep(2)
        raise DrillError('JOB_WAIT_TIMEOUT_RECONCILE_EXISTING_ID')

    def readback(self, stage, snapshot_id, copy_id, backend):
        from vaultrewind.core.manifest import sha256_file, verify_snapshot
        from vaultrewind.core.sqlite import validate_sqlite
        from vaultrewind.server.models import Repository, Snapshot, SnapshotCopy, StorageDestination
        require(backend == 'local' or (self.args.phase == 'retry' and self.state.get('retry_grant')),
                'REVOKED_DRIVE_READ_FORBIDDEN')
        with self.sessions() as db:
            point, item = db.get(Snapshot, snapshot_id), db.get(SnapshotCopy, copy_id)
            require(point and item, 'READBACK_CATALOG_POINT_MISSING')
            repository = db.get(Repository, item.repository_id)
            dest = db.get(StorageDestination, repository.destination_id)
            require(point.instance_id == repository.instance_id == SOURCE_ID and item.snapshot_id == point.id and
                    item.state == 'complete' and point.completeness == 'complete' and dest.backend == backend and
                    not dest.archived and item.manifest_hash == point.manifest_hash and
                    re.fullmatch(r'[0-9a-f]{64}', item.restic_snapshot_id or ''), 'EXACT_COMPLETE_READBACK_REQUIRED')
            if backend == 'drive':
                require(dest.id == self.destination, 'WRONG_DRIVE_DESTINATION')
            repo_id, restic_id, expected = repository.id, item.restic_snapshot_id, point.manifest_hash
        record = self.state['readbacks'].setdefault(stage, {})
        target, work = self.root / (stage + '-restored'), self.root / (stage + '-adapter')
        require(all(not p.is_symlink() for p in (target, work)), 'READBACK_PATH_UNSAFE')
        if not record.get('complete'):
            require(not record.get('attempted'), 'READBACK_INTERRUPTED_PRESERVE_PRIVATE_WORK')
            record.update(attempted=True, snapshot_id=snapshot_id, copy_id=copy_id)
            self.save()
            self.credential_quiet()
            work.mkdir(mode=0o700, exist_ok=False)
            # No unconditional finally cleanup: the product context owns token/session recovery.
            with self.adapters.repository(repo_id, work) as repo:
                restored = repo.restore(restic_id, target, expected_manifest_hash=expected)
            require(restored.get('restored_bytes_verified'), 'RESTIC_RESTORE_VERIFY_NOT_PROVEN')
        checked = verify_snapshot(target, expected)
        manifest = checked['manifest']
        require(manifest['snapshot_uuid'] == snapshot_id and manifest['instance_uuid'] == SOURCE_ID and
                manifest['deployment_fingerprint'] == self.state['source_configuration']['fingerprint'],
                'READBACK_IMMUTABLE_MANIFEST_BINDING_MISMATCH')
        require(sha256_file(target / 'images/vaultwarden.tar') == manifest['image_archive_hash'],
                'READBACK_SAVED_IMAGE_HASH_MISMATCH')
        database = validate_sqlite(target / 'data')
        require(database['database_integrity'] == 'ok' and not (target / 'data/db.sqlite3-wal').exists() and
                not (target / 'data/db.sqlite3-shm').exists(), 'READBACK_STANDALONE_SQLITE_REQUIRED')
        files = {e['path']: e['sha256'] for e in manifest['inventory'] if e['type'] == 'file'}
        private_write(self.root / (stage + '-manifest.json'), manifest)
        record.update(complete=True, backend=backend, snapshot_id=snapshot_id, copy_id=copy_id,
            repository_id=repo_id, manifest_hash=expected, whole_file_map_sha256=digest(files),
            restored_bytes_verified=True, saved_image_inventory_verified=True, sqlite_integrity='ok',
            file_count=len(files), logical_bytes=checked['logical_bytes'], user_login_tested=False)
        self.save()
        return record

    def base_readback(self, stage):
        base = self.state['base']
        proof = self.readback(stage, base['snapshot_id'], base['local_copy_id'], 'local')
        require(proof['manifest_hash'] == base['manifest_hash'] and
                proof['whole_file_map_sha256'] == base['whole_file_map_sha256'], 'HISTORICAL_LOCAL_BYTES_CHANGED')

    def fault(self):
        if self.state.get('fault_proven'):
            progress('FAULT_ALREADY_PROVEN')
            return
        record = self.state['steps'].get('fault', {})
        if not record.get('attempted'):
            self.idle_source()
            self.credential_quiet()
            grant = self.credential(revoked=True)
            self.state['revoked_credential'] = grant
            self.save()
            self.base_readback('base_before_fault')
            if 'source_before_fault' not in self.state:
                self.state['source_before_fault'] = self.source_witness()
                self.save()
            self.install_policy()
        self.submit('fault')
        job = self.wait('fault')
        snapshot_id = job['result'].get('snapshot_id')
        require(snapshot_id, 'AUTH_FAULT_DID_NOT_CREATE_SNAPSHOT')
        snapshot = self.request('GET', '/snapshots/' + identifier(snapshot_id))
        locals_ = [c for c in snapshot['copies'] if c['backend'] == 'local' and c['state'] == 'complete']
        base_repo = self.recovery['local_readback']['repository_id']
        locals_ = [c for c in locals_ if c['repository_id'] == base_repo]
        require(len(locals_) == 1, 'SAME_REQUIRED_LOCAL_REPOSITORY_COPY_REQUIRED')
        local = locals_[0]
        # Persist observed IDs before assertions; a different real result remains inspectable.
        self.state.update(snapshot_id=snapshot_id, local_copy_id=local['id'])
        selected = [c for c in snapshot['copies'] if c['destination_id'] == self.destination]
        if len(selected) == 1:
            self.state.update(drive_copy_id=selected[0]['id'], drive_repository_id=selected[0]['repository_id'])
            self.state['fault_copy_observation'] = {k: selected[0].get(k) for k in
                ('id', 'repository_id', 'destination_id', 'backend', 'state', 'error_code')}
        self.save()
        validate_fault(job, snapshot, self.destination, local['id'])
        self.readback('fault_local', snapshot_id, local['id'], 'local')
        after = self.source_witness()
        self.state['source_after_fault'] = after
        self.save()
        compare_source(self.state['source_before_fault'], after, retry=False)
        self.base_readback('base_after_fault')
        self.state['fault_proven'] = True
        self.save()

    def retry(self):
        require(self.state.get('fault_proven') and self.state.get('policy_restored') and
                self.state['readbacks'].get('fault_local', {}).get('complete'), 'PROVEN_FAULT_AND_LOCAL_READBACK_REQUIRED')
        original = self.lookup_job(self.state['steps']['fault'])
        require({k: original[k] for k in JOB_FIELDS} == self.state['steps']['fault']['terminal_observation'],
                'ORIGINAL_PARTIAL_JOB_CHANGED')
        record = self.state['steps'].get('retry', {})
        if not record.get('attempted'):
            self.credential_quiet()
        grant = self.credential(revoked=False)
        self.state['retry_grant'] = grant
        self.save()
        if not record.get('attempted'):
            self.idle_source()
            snapshot = self.request('GET', '/snapshots/' + self.state['snapshot_id'])
            validate_fault(original, snapshot, self.destination, self.state['local_copy_id'])
            self.state['source_before_retry'] = self.source_witness()
            self.save()
        self.submit('retry')
        job = self.wait('retry')
        snapshot = self.request('GET', '/snapshots/' + self.state['snapshot_id'])
        observation = {k: job[k] for k in JOB_FIELDS}
        if observation not in self.state['retry_attempts']:
            self.state['retry_attempts'].append(observation)
            self.save()
        validate_retry(job, self.state, snapshot)
        drive = self.readback('retry_drive', self.state['snapshot_id'], self.state['drive_copy_id'], 'drive')
        local = self.readback('fault_local', self.state['snapshot_id'], self.state['local_copy_id'], 'local')
        require(drive['manifest_hash'] == local['manifest_hash'] and
                drive['whole_file_map_sha256'] == local['whole_file_map_sha256'], 'RETRY_DRIVE_DIFFERS_FROM_FAULT_LOCAL')
        # Fresh grant also proves the original historical Drive point is still readable.
        self.base_readback('base_after_retry')
        historical = self.readback('base_drive_after_reconnect', self.state['base']['snapshot_id'],
                                   self.state['base']['drive_copy_id'], 'drive')
        require(historical['whole_file_map_sha256'] == self.state['base']['whole_file_map_sha256'],
                'HISTORICAL_DRIVE_BYTES_CHANGED')
        after = self.source_witness()
        self.state['source_after_retry'] = after
        self.save()
        compare_source(self.state['source_before_retry'], after, retry=True)
        preserved = self.lookup_job(self.state['steps']['fault'])
        require({k: preserved[k] for k in JOB_FIELDS} == self.state['steps']['fault']['terminal_observation'],
                'ORIGINAL_PARTIAL_JOB_CHANGED')
        self.state['retry_proven'] = True
        self.save()

    def final_verification(self):
        """Even an unexpected real outcome must retain independent source/base checks."""
        before = self.state.get('source_before_' + self.args.phase)
        if not before:
            return
        self.idle_source()  # An ongoing job stays intact; ROOT reconciles its recorded ID.
        self.base_readback('base_final_' + self.args.phase)
        if self.state.get('snapshot_id') and self.state.get('local_copy_id'):
            self.readback('fault_local', self.state['snapshot_id'], self.state['local_copy_id'], 'local')
        after = self.source_witness()
        self.state['source_final_' + self.args.phase] = after
        self.save()
        compare_source(before, after, retry=self.args.phase == 'retry')

    def publish(self):
        complete = bool(self.state.get('last_execution_succeeded') and
                        self.state.get('fault_proven') and self.state.get('retry_proven') and
                        self.state.get('policy_restored'))
        report = {k: self.state.get(k) for k in ('version', 'source_id', 'destination_id', 'run_id', 'base',
            'snapshot_id', 'local_copy_id', 'drive_copy_id', 'drive_repository_id', 'fault_proven', 'retry_proven',
            'readbacks', 'source_before_fault', 'source_after_fault', 'source_before_retry', 'source_after_retry',
            'fault_copy_observation', 'policy_restored', 'failures', 'retry_attempts')}
        report['final_source_checks'] = {stage: self.state.get('source_final_' + stage) for stage in ('fault', 'retry')}
        report['jobs'] = {name: {k: value for k, value in record.items() if k in
            {'job_id', 'job', 'result', 'terminal_observation', 'attempted'}}
            for name, record in self.state['steps'].items()}
        report.update(provider='google_drive', result='actual_auth_fault_same_snapshot_retry_proven' if complete else 'partial',
            recorded_at=datetime.now(UTC).isoformat(), actual_execution=True, user_login_tested=False,
            AC14_release_verified=False, historical_drive_read_with_revoked_grant=False,
            oauth_credentials_changed_by_this_script=False, application_started=False,
            awaiting_private_ui_reconnect=bool(self.state.get('fault_proven') and not self.state.get('retry_proven')))
        payload = json.dumps(report, indent=2) + '\n'
        require(all(secret not in payload for secret in self.secret_values if len(secret) >= 8),
                'PUBLIC_EVIDENCE_SECRET_DETECTED')
        path = PROJECT / 'docs/evidence/drive-auth-failure.json'
        require(all(not p.is_symlink() for p in (path, *path.parents)), 'EVIDENCE_PATH_UNSAFE')
        if path.exists():
            prior = json.loads(private_read(path))
            require(prior.get('run_id') == self.run_id and prior.get('destination_id') == self.destination,
                    'OTHER_AUTH_EVIDENCE_REQUIRES_ROOT_REVIEW')
        private_write(path, report)

    def execute(self):
        failure = None
        self.state['last_execution_succeeded'] = False
        self.save()
        try:
            self.catalog_binding()
            if self.args.phase == 'fault':
                self.fault()
            else:
                self.retry()
        except Exception as error:  # noqa: BLE001 - never print private exception details.
            failure = safe_code(error)
            self.state['failures'].append({'phase': self.args.phase, 'code': failure})
            self.save()
        finally:
            try:
                self.restore_policy()
            except Exception as error:  # noqa: BLE001 - retain both operation and restoration errors.
                code = safe_code(error)
                self.state['policy_restored'] = False
                self.state['failures'].append({'phase': 'policy_restore', 'code': code})
                self.save()
                failure = failure or code
            try:
                self.final_verification()
            except Exception as error:  # noqa: BLE001
                code = safe_code(error)
                self.state['failures'].append({'phase': 'final_verification', 'code': code})
                self.save()
                failure = failure or code
            self.state['last_execution_succeeded'] = failure is None
            self.save()
            try:
                self.publish()
            except Exception as error:  # noqa: BLE001
                code = safe_code(error)
                self.state['last_execution_succeeded'] = False
                self.state['failures'].append({'phase': 'publication', 'code': code})
                self.save()
                failure = failure or code
        if failure:
            raise DrillError(failure)
        progress('AUTH_FAULT_PROVEN_AWAITING_PRIVATE_UI_RECONNECT' if self.args.phase == 'fault' else
                 'AUTH_SAME_SNAPSHOT_RETRY_PROVEN')

    def close(self):
        self.http.close()
        self.engine.dispose()


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--root-go', default='')
    parser.add_argument('--dedicated-test-account', action='store_true')
    parser.add_argument('--destination-id', type=identifier)
    parser.add_argument('--run-id', type=identifier)
    parser.add_argument('--phase', choices=('fault', 'retry'))
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    if not args.execute:
        print(json.dumps({'code': 'PREPARED_AUTH_FAULT_NOT_EXECUTED', 'private_files_opened': 0,
            'network_sql_provider_ssh_docker_calls': 0, 'evidence_written': False,
            'requires': ['ROOTGO_AUTH_FAULT', 'dedicated test account', 'matching recovery run UUID',
                         'completed roundtrip alternate retention and real revocation',
                         'fresh private UI Reconnect before retry']}), flush=True)
        return 0
    drill = None
    try:
        require_execution(args)
        os.umask(0o077)
        with execution_lock(args):
            try:
                drill = AuthFaultDrill(args)
                drill.execute()
            finally:
                if drill is not None:
                    drill.close()
    except Exception as error:  # noqa: BLE001 - secrets never reach stdout or a traceback.
        progress(safe_code(error))
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

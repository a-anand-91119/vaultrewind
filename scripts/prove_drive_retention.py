#!/usr/bin/env python3
"""Parked Drive retention proof; no runtime construction before ROOTGO_LIVE_RETENTION.

Only new disposable repositories are writable. Historical times belong solely
to newly created, explicitly labelled fixture trees and an isolated catalog.
No native snapshot row, source, repository or controller clock is changed.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import stat
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

PROJECT = Path(__file__).resolve().parents[1]
PRIVATE = PROJECT / '.runtime/controller'
CONTROLLER = Path('/srv/vaultrewind-native-controller')
SOURCE_ID = '46ac8eb9-1854-4fc6-924f-af14c6b7d0c2'
ALTERNATE_ID = 'b05f7958-3d3b-48d6-a8f2-8eb900533149'
RELEASE = 'ROOTGO_LIVE_RETENTION'
DAYS = 30


class DrillError(Exception):
    """Public codes only. Raw SQL/provider errors must never reach stdout."""


def require(value, code):
    if not value:
        raise DrillError(code)


def identifier(value):
    try:
        parsed = UUID(value)
    except (ValueError, AttributeError, TypeError):
        raise argparse.ArgumentTypeError('A canonical UUID is required.') from None
    if str(parsed) != value or parsed.version != 4:
        raise argparse.ArgumentTypeError('A canonical version-4 UUID is required.')
    return value


def planner_time(value):
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
            raise ValueError()
    except (ValueError, AttributeError):
        raise argparse.ArgumentTypeError('An explicit UTC fixture planner time is required.') from None
    return parsed.astimezone(UTC)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def require_execution(args):
    require(args.execute and args.root_go == RELEASE and args.dedicated_test_account and
            args.destination_id and args.run_id and args.planner_time,
            'DRIVE_PARKED_ROOTGO_LIVE_RETENTION_AND_EXACT_DEDICATED_SCOPE_REQUIRED')
    for value in (args.destination_id, args.run_id):
        identifier(value)
    require(args.planner_time.tzinfo is not None and args.planner_time.utcoffset() == timedelta(0),
            'UTC_FIXTURE_PLANNER_TIME_REQUIRED')


def fixture_records(current, destination_id):
    """All identities are generated here; no CLI override can select an existing repository."""
    primary, sentinel = str(uuid4()), str(uuid4())
    cutoff = current - timedelta(days=DAYS)
    times = {'expired': cutoff - timedelta(seconds=1), 'boundary': cutoff,
             'within_one': cutoff + timedelta(seconds=1), 'within_two': cutoff + timedelta(seconds=2),
             'pinned': cutoff - timedelta(days=3), 'newest': current - timedelta(hours=1),
             'other_instance': cutoff - timedelta(days=4)}
    repositories = [{'id': str(uuid4()), 'instance_id': identity, 'destination_id': destination_id}
                    for identity in (primary, sentinel)]
    records = []
    for label, captured in times.items():
        repository = repositories[1 if label == 'other_instance' else 0]
        records.append({'label': label, 'snapshot_id': str(uuid4()), 'copy_id': str(uuid4()),
                        'repository_id': repository['id'], 'instance_id': repository['instance_id'],
                        'captured_at': captured.isoformat()})
    return repositories, records


def guard_new_scope(repositories, records, existing_ids):
    ids = [r['id'] for r in repositories] + [r['instance_id'] for r in repositories]
    ids += [r[key] for r in records for key in ('snapshot_id', 'copy_id')]
    require(len(ids) == len(set(ids)) and not set(ids) & (set(existing_ids) | {SOURCE_ID, ALTERNATE_ID}),
            'FIXTURE_IDENTITIES_MUST_ALL_BE_NEW')
    for value in ids:
        identifier(value)
    require(len(repositories) == 2 and len({r['destination_id'] for r in repositories}) == 1,
            'EXACT_TWO_DISPOSABLE_REPOSITORIES_REQUIRED')
    for record in records:
        require(any(record['repository_id'] == r['id'] and record['instance_id'] == r['instance_id']
                    for r in repositories), 'FIXTURE_COPY_OUTSIDE_NEW_SCOPE')


def exact_deletions(preview, repeated, records, repository):
    """Bind product copy IDs to full restic IDs, refusing broadened or changed plans."""
    require(preview == repeated, 'RETENTION_PLAN_CHANGED')
    require(not preview['frozen'] and not preview['freeze_reasons'] and preview['retention_days'] == DAYS,
            'RETENTION_FROZEN_OR_POLICY_CHANGED')
    require(preview['instance_id'] == repository['instance_id'], 'RETENTION_INSTANCE_SCOPE_MISMATCH')
    by_copy = {r['copy_id']: r for r in records if not r.get('expired')}
    entries = {e['copy_id']: e for e in preview['entries']}
    wanted = preview['copy_ids']
    require(wanted and len(wanted) == len(set(wanted)) and
            set(wanted) == {e['copy_id'] for e in preview['entries'] if e['eligible']},
            'EXACT_NONEMPTY_PRODUCT_DELETION_SET_REQUIRED')
    result = []
    for copy_id in wanted:
        record, entry = by_copy.get(copy_id), entries.get(copy_id)
        require(record is not None and entry is not None, 'UNKNOWN_DELETION_COPY')
        require(record['repository_id'] == repository['id'] == entry['repository_id'] and
                record['instance_id'] == repository['instance_id'] and
                record['snapshot_id'] == entry['snapshot_id'] and
                not entry['protections'] and entry['eligible'], 'DELETION_SCOPE_OR_PROTECTION_MISMATCH')
        restic_id = record.get('restic_snapshot_id', '')
        require(isinstance(restic_id, str) and re.fullmatch(r'[0-9a-f]{64}', restic_id),
                'FULL_EXACT_RESTIC_ID_REQUIRED')
        result.append(restic_id)
    require(len(result) == len(set(result)), 'RESTIC_COPY_ID_ALIAS_REJECTED')
    return sorted(result)


def verify_provider_set(actual, records, repository):
    expected = {r['restic_snapshot_id']: r for r in records
                if r['repository_id'] == repository['id'] and not r.get('expired')}
    require(len(actual) == len(expected) and {r['restic_snapshot_id'] for r in actual} == set(expected),
            'UNEXPECTED_PROVIDER_SNAPSHOT_SET')
    for found in actual:
        record = expected[found['restic_snapshot_id']]
        require(found['instance_uuid'] == repository['instance_id'] and
                found['snapshot_uuid'] == record['snapshot_id'] and
                found['manifest_hash'] == record['manifest_hash'], 'PROVIDER_SNAPSHOT_IDENTITY_CHANGED')


def verify_forget_result(result, wanted):
    require(result.get('complete') is True and result.get('exit_code') == 0 and not result.get('error_code')
            and result.get('requested') == wanted and sorted(result.get('removed', [])) == wanted
            and not result.get('retained') and not result.get('already_absent'),
            'EXACT_PROVIDER_DELETION_NOT_PROVEN')


def private_read(path):
    require(all(not p.is_symlink() for p in (path, *path.parents)), 'PRIVATE_PATH_SYMLINK_REJECTED')
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o077,
                'PRIVATE_FILE_REQUIRED')
        return stream.read()


def private_write(path, value):
    from vaultrewind.security.privatefiles import atomic_private_write
    atomic_private_write(path, json.dumps(value, indent=2).encode())


def seed_catalog(factory, repositories, records, destination_id):
    """Only the isolated SQLite catalog receives fixture rows; times are immutable after insert."""
    from vaultrewind.server.models import (
        BackupPolicy,
        Instance,
        PolicyDestination,
        Repository,
        Secret,
        Snapshot,
        SnapshotCopy,
        SnapshotProtection,
        StorageDestination,
    )
    with factory.begin() as db:
        secret = Secret(id=str(uuid4()), kind='fixture', owner_scope='DISPOSABLE_RETENTION_FIXTURE',
                        envelope='NO_CREDENTIALS_IN_FIXTURE_CATALOG')
        db.add(secret)
        db.flush()
        db.add(StorageDestination(id=destination_id, name='DISPOSABLE fixture destination', backend='drive',
                                  configuration_secret_id=secret.id))
        db.flush()
        for repo in repositories:
            db.add(Instance(id=repo['instance_id'], name='DISPOSABLE RETENTION FIXTURE', container_id='NONE',
                            configuration_secret_id=secret.id, physical_identity=digest(repo),
                            fingerprint=digest(repo), backup_health='healthy'))
        db.flush()
        for repo in repositories:
            db.add(Repository(id=repo['id'], instance_id=repo['instance_id'], destination_id=destination_id,
                              configuration_secret_id=secret.id, key_id=secret.id,
                              physical_identity=digest(repo), health='healthy'))
        db.flush()
        for repo in repositories:
            policy = BackupPolicy(instance_id=repo['instance_id'], enabled=False, retention_days=DAYS)
            db.add(policy)
            db.flush()
            db.add(PolicyDestination(policy_id=policy.id, repository_id=repo['id'], required=True))
        for record in records:
            captured = datetime.fromisoformat(record['captured_at'])
            db.add(Snapshot(id=record['snapshot_id'], instance_id=record['instance_id'],
                            captured_at=captured, capture_started_at=captured, trigger='manual',
                            manifest_hash=record['manifest_hash'], completeness='complete',
                            image_id='fixture-recorded-image', vaultwarden_version='fixture', source_state='stopped'))
        db.flush()
        for record in records:
            db.add(SnapshotCopy(id=record['copy_id'], snapshot_id=record['snapshot_id'],
                                repository_id=record['repository_id'], state='complete',
                                restic_snapshot_id=record['restic_snapshot_id'], manifest_hash=record['manifest_hash']))
        db.flush()
        for record in records:
            if record['label'] == 'pinned':
                db.add(SnapshotProtection(snapshot_id=record['snapshot_id'], reason='pin'))


class RetentionDrill:
    def __init__(self, args):
        require_execution(args)  # Must precede imports, paths, credentials, clients and SQL.
        from vaultrewind.server.adapters import Adapters, SQLCredentialStore
        from vaultrewind.server.db import make_engine, sessions
        from vaultrewind.server.settings import Settings
        require(args.planner_time > datetime.now(UTC) + timedelta(days=365), 'FIXED_FUTURE_FIXTURE_TIME_REQUIRED')
        evidence = PROJECT / 'docs/evidence/drive-retention.json'
        require(not evidence.exists() and not evidence.is_symlink(), 'EXISTING_EVIDENCE_REQUIRES_ROOT_REVIEW')
        self.args = args
        self.root = PROJECT / '.runtime/drive-retention' / args.run_id
        require(all(not p.is_symlink() for p in (self.root, *self.root.parents)), 'RUNTIME_SYMLINK_REJECTED')
        self.root.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        require(not self.root.parent.stat().st_mode & 0o077, 'PRIVATE_RUNTIME_PARENT_REQUIRED')
        # An interrupted run is a recovery task, never an excuse to repeat init/forget/prune.
        self.root.mkdir(mode=0o700, exist_ok=False)
        repositories, records = fixture_records(args.planner_time, args.destination_id)
        self.state = {'version': 1, 'status': 'running', 'run_id': args.run_id,
                      'destination_id': args.destination_id, 'repositories': repositories, 'records': records,
                      'synthetic_fixture_capture_times_only': True, 'planner_time': args.planner_time.isoformat(),
                      'rounds': [], 'workspace_retained': True}
        self.save()
        self.settings = Settings(database_url=private_read(PRIVATE / 'database-url').decode().strip(),
            master_key_file=PRIVATE / 'master', bootstrap_secret_file=PRIVATE / 'bootstrap',
            staging_dir=CONTROLLER / 'staging', local_storage_root=CONTROLLER / 'backups',
            provider_credential_state_dir=args.credential_state_dir)
        self.engine = make_engine(self.settings.database_url)
        require(self.engine.url.get_backend_name() == 'postgresql' and
                self.engine.url.host in {None, 'localhost', '127.0.0.1'}, 'PRIVATE_NATIVE_POSTGRES_REQUIRED')
        self.sessions = sessions(self.engine)
        self.adapters = Adapters(self.settings, self.sessions)
        self.store = SQLCredentialStore(self.adapters, self.guard)
        self.box = self.adapters.secrets.box()
        self.secret_values = []
        self.baseline = None

    def save(self):
        private_write(self.root / 'checkpoint.json', self.state)

    def destination_state(self):
        from vaultrewind.server.models import StorageDestination
        from vaultrewind.storage.credentials import credential_context
        with self.sessions() as db:
            destination = db.get(StorageDestination, self.args.destination_id)
            require(destination is not None and destination.backend == 'drive' and not destination.archived,
                    'EXACT_EXISTING_DRIVE_DESTINATION_REQUIRED')
            configuration = self.adapters.secrets.get(db, destination.configuration_secret_id)
            revision = destination.revision
        stored = self.store.load(self.args.destination_id)
        require(stored is not None, 'AUTHORIZE_DEDICATED_DESTINATION_IN_PRIVATE_APP_FIRST')
        credential = self.box.decrypt(stored.envelope, context=credential_context(self.args.destination_id))
        require(credential.get('type') == 'google_drive_oauth' and credential.get('scope') == 'drive.file'
                and credential.get('grant_id') and not credential.get('revoked') and not credential.get('revoked_at')
                and credential.get('folder_id') == configuration.get('folder_id') and configuration.get('folder_id')
                and stored.generation, 'CURRENT_AUTHORIZED_DEDICATED_MY_DRIVE_GRANT_REQUIRED')
        require(credential.get('token', {}).get('access_token') and credential['token'].get('refresh_token'),
                'REFRESHABLE_PRIVATE_GRANT_REQUIRED')
        self.secret_values.extend(str(credential.get(k, '')) for k in ('client_id', 'client_secret', 'folder_id'))
        self.secret_values.extend(str(v) for v in credential['token'].values() if isinstance(v, str))
        identity = {'configuration_sha256': digest(configuration), 'destination_revision': revision,
                    'credential_generation': stored.generation, 'grant_sha256': digest(credential['grant_id'])}
        return identity, configuration

    def guard(self):
        identity, _ = self.destination_state()
        require(self.baseline is not None and identity == self.baseline, 'DESTINATION_OR_GRANT_CHANGED')

    @contextmanager
    def exclusive_destination(self):
        from sqlalchemy import select

        from vaultrewind.server.models import ResourceLease
        from vaultrewind.storage.credentials import credential_lock
        directory = self.store.state_directory
        require(directory.is_absolute() and all(not p.is_symlink() for p in (directory, *directory.parents)),
                'CREDENTIAL_STATE_DIRECTORY_UNSAFE')
        # Queue users coordinate on this row; hold it for the whole direct provider drill.
        # The product session acquires its own session lock and persists generation/CAS updates.
        with self.sessions.begin() as db:
            lease = db.scalar(select(ResourceLease).where(
                ResourceLease.resource_key == 'credential:' + self.args.destination_id).with_for_update(nowait=True))
            require(lease is not None and lease.owner_job_id is None, 'IDLE_EXISTING_CREDENTIAL_LEASE_REQUIRED')
            with credential_lock(directory / 'session-locks', self.args.destination_id, timeout=1):
                for child, pattern in (('pending', '*.pending-credential'), ('sessions', '*.drive-session')):
                    path = directory / child
                    if path.exists() or path.is_symlink():
                        require(not path.is_symlink() and path.is_dir() and path.stat().st_uid == os.geteuid()
                                and not path.stat().st_mode & 0o077, 'CREDENTIAL_STATE_DIRECTORY_UNSAFE')
                        require(not list(path.glob(self.args.destination_id + '.' + pattern)),
                                'PENDING_OR_REGISTERED_SESSION_REQUIRES_PRODUCT_RECOVERY')
            self.baseline, self.configuration = self.destination_state()
            self.state.update(self.baseline)
            self.save()
            yield
            self.guard()

    def verify_prior_roundtrip(self):
        from vaultrewind.core.manifest import sha256_file, verify_snapshot
        path = PROJECT / '.runtime/drive-proof' / self.args.run_id
        checkpoint = json.loads(private_read(path / 'checkpoint.json'))
        require(checkpoint.get('version') == 1 and checkpoint.get('run_id') == self.args.run_id and
                checkpoint.get('destination_id') == self.args.destination_id and
                checkpoint.get('source_id') == SOURCE_ID and checkpoint.get('dedicated_test_account_acknowledged')
                and checkpoint.get('configuration_sha256') == self.baseline['configuration_sha256'],
                'MATCHED_DEDICATED_RECOVERY_RUN_REQUIRED')
        for stage in ('drive_readback', 'local_readback'):
            proof = checkpoint.get(stage, {})
            require(proof.get('complete') and proof.get('restored_bytes_verified') and
                    proof.get('saved_image_inventory_verified') and proof.get('sqlite_integrity') == 'ok',
                    'GENUINE_VERIFIED_ROUNDTRIP_BYTES_REQUIRED')
        expected = checkpoint['local_readback']['manifest_hash']
        require(expected == checkpoint['drive_readback']['manifest_hash'] and
                checkpoint['local_readback']['whole_file_map_sha256'] ==
                checkpoint['drive_readback']['whole_file_map_sha256'], 'ROUNDTRIP_CONTENT_MISMATCH')
        root = path / 'local_readback-restored'
        require(all(not p.is_symlink() for p in (root, *root.parents)), 'FIXTURE_INPUT_PATH_UNSAFE')
        checked = verify_snapshot(root, expected)
        manifest = checked['manifest']
        require(manifest['instance_uuid'] == SOURCE_ID and manifest['snapshot_uuid'] == checkpoint['snapshot_id']
                and sha256_file(root / 'images/vaultwarden.tar') == manifest['image_archive_hash'],
                'ROUNDTRIP_INPUT_IDENTITY_OR_IMAGE_CHANGED')
        self.state['input_snapshot_id'] = checkpoint['snapshot_id']
        self.state['input_manifest_hash'] = expected
        self.save()
        return root, manifest

    def check_fresh_identities(self):
        from sqlalchemy import select

        from vaultrewind.server.models import Instance, Repository, Snapshot, SnapshotCopy
        ids = {r[key] for r in self.state['repositories'] for key in ('id', 'instance_id')}
        ids |= {r[key] for r in self.state['records'] for key in ('snapshot_id', 'copy_id')}
        existing = set()
        with self.sessions() as db:
            for model in (Instance, Repository, Snapshot, SnapshotCopy):
                existing.update(db.scalars(select(model.id).where(model.id.in_(ids))))
            require(not list(db.scalars(select(Repository.id).where(Repository.instance_id.in_(ids)))),
                    'FIXTURE_INSTANCE_ALREADY_HAS_NATIVE_REPOSITORY')
        guard_new_scope(self.state['repositories'], self.state['records'], existing)

    def check_absent_provider_prefixes(self):
        from vaultrewind.storage.drive import REMOTE, DriveCredentialSession, _rclone_ok
        # Read the existing layout root, never probe/delete a native repository.
        with DriveCredentialSession(self.args.destination_id, self.store, self.box,
                folder_id=self.configuration['folder_id'], lock_dir=self.root / 'unused-locks',
                runtime_dir=self.root / 'prefix-inspection') as session:
            raw = _rclone_ok(session, ['lsjson', '--max-depth', '1', f'{REMOTE}:vaultrewind'], 'list')
            entries = json.loads(raw)
            require(isinstance(entries, list), 'PROVIDER_PREFIX_LIST_INVALID')
            names = {e['Path'] for e in entries}
            require(all(r['instance_id'] not in names for r in self.state['repositories']),
                    'FIXTURE_PROVIDER_PREFIX_ALREADY_EXISTS')
        self.guard()

    @contextmanager
    def repository(self, selected):
        from vaultrewind.storage.providers import open_repository, repository_location
        self.guard()
        require(selected in self.state['repositories'], 'REPOSITORY_OUTSIDE_DISPOSABLE_SCOPE')
        location = repository_location('drive', self.configuration, selected['instance_id'], self.args.destination_id)
        with open_repository('drive', self.configuration, None, instance_id=selected['instance_id'],
                destination_id=self.args.destination_id, password=self.passwords[selected['id']],
                repository_id=selected.get('restic_repository_id'), location=location,
                work_dir=self.root / ('adapter-' + selected['id']), credential_store=self.store, box=self.box) as repo:
            require(repo.config.location == location and repo.config.instance_uuid == selected['instance_id'],
                    'ADAPTER_SCOPE_MISMATCH')
            yield repo
        self.guard()

    def prepare_tree(self, original, metadata, record):
        import shutil

        from vaultrewind.core.manifest import create_manifest, manifest_hash, verify_snapshot
        # Preserve hardlink relationships inside each new tree without ever linking to input bytes.
        inodes = {}

        def copier(source, target):
            info = os.stat(source)
            inode = (info.st_dev, info.st_ino)
            if inode in inodes:
                os.link(inodes[inode], target)
            else:
                shutil.copy2(source, target)
                inodes[inode] = target
            return target

        root = self.root / ('tree-' + record['snapshot_id'])
        shutil.copytree(original, root, symlinks=True, copy_function=copier)
        (root / 'data' / ('.DISPOSABLE-retention-' + record['snapshot_id'])).write_bytes(os.urandom(65536))
        clean = copy.deepcopy(metadata)
        clean.pop('inventory', None)
        clean.update(snapshot_uuid=record['snapshot_id'], instance_uuid=record['instance_id'],
                     capture_started_at=record['captured_at'], captured_at=record['captured_at'],
                     consistency_mode='independent_disposable_retention_fixture_from_verified_readback',
                     retention_fixture={'synthetic_capture_time': True, 'run_id': self.args.run_id,
                                        'original_manifest_hash': self.state['input_manifest_hash']})
        manifest = create_manifest(root, clean)
        record['manifest_hash'] = manifest_hash(manifest)
        verify_snapshot(root, record['manifest_hash'])
        self.save()
        return root

    def readback(self, selected, record, phase):
        from vaultrewind.core.manifest import sha256_file, verify_snapshot
        require(record['repository_id'] == selected['id'] and not record.get('expired'), 'READBACK_SCOPE_MISMATCH')
        self.state['current_action'] = {'phase': phase, 'operation': 'restore', 'copy_id': record['copy_id']}
        self.save()
        target = self.root / (phase + '-' + record['snapshot_id'])
        with self.repository(selected) as repo:
            outcome = repo.restore(record['restic_snapshot_id'], target,
                                   expected_manifest_hash=record['manifest_hash'])
        checked = verify_snapshot(target, record['manifest_hash'])
        manifest = checked['manifest']
        require(outcome.get('restored_bytes_verified') and checked['database_integrity'] == 'ok' and
                checked['attachment_references_verified'] and manifest['snapshot_uuid'] == record['snapshot_id']
                and manifest['instance_uuid'] == selected['instance_id'] and
                sha256_file(target / 'images/vaultwarden.tar') == manifest['image_archive_hash'] and
                not (target / 'data/db.sqlite3-wal').exists() and not (target / 'data/db.sqlite3-shm').exists(),
                'COMPLETE_RETAINED_POINT_READBACK_NOT_PROVEN')
        stored_inventory = json.loads((target / 'manifest/inventory.json').read_bytes())
        require(stored_inventory == manifest['inventory'], 'INVENTORY_SIDECAR_MISMATCH')
        files = {e['path']: e['sha256'] for e in manifest['inventory'] if e['type'] == 'file'}
        return {'copy_id': record['copy_id'], 'restic_snapshot_id': record['restic_snapshot_id'],
                'manifest_hash': record['manifest_hash'], 'whole_file_map_sha256': digest(files),
                'file_count': len(files), 'complete_file_manifest_checked': True, 'sqlite_integrity': 'ok',
                'attachment_references_verified': True, 'saved_image_hash_verified': True,
                'restored_bytes_verified': True, 'fresh_provider_restore': True,
                'application_started': False, 'user_login_tested': False}

    def expire(self, factory, current, labels, phase):
        from vaultrewind.server.models import SnapshotCopy
        from vaultrewind.server.policy import retention_preview
        selected = self.state['repositories'][0]
        records = self.state['records']
        with factory() as db:
            preview = retention_preview(db, selected['instance_id'], current=current)
        require(set(preview['copy_ids']) == {r['copy_id'] for r in records if r['label'] in labels},
                'EXPECTED_ROLLING_BOUNDARY_OR_NEWEST_PROTECTION_NOT_PROVEN')
        # This isolated catalog has a single owner. The native catalog and clock are never changed.
        with self.repository(selected) as repo, factory() as db:
            repo.describe()
            verify_provider_set(repo.list_snapshots(), records, selected)
            repeated = retention_preview(db, selected['instance_id'], current=current)
            wanted = exact_deletions(preview, repeated, records, selected)
            round_state = {'phase': phase, 'planner_time': current.isoformat(), 'preview': preview,
                           'requested_exact_restic_ids': wanted, 'forget_attempted': True}
            self.state['rounds'].append(round_state)
            self.save()  # Durable intent before any provider deletion; no automatic retry on lost response.
            self.guard()
            result = repo.forget(wanted)
            round_state['forget'] = result
            self.save()
            verify_forget_result(result, wanted)
            for record in records:
                if record['restic_snapshot_id'] in wanted:
                    record['expired'] = True
            verify_provider_set(repo.list_snapshots(), records, selected)
            round_state['post_forget_exact_remaining_set_verified'] = True
            self.save()
            round_state['prune_attempted'] = True
            self.save()
            self.guard()
            round_state['prune'] = repo.prune(verify=True)
            self.save()
            require(round_state['prune'].get('pruned') and round_state['prune']['check'].get('ok'),
                    'PRUNE_AND_STRUCTURE_CHECK_NOT_PROVEN')
            round_state['check'] = repo.check(read_data=True)
            self.save()
            require(round_state['check'].get('ok') and round_state['check'].get('full_data_verified'),
                    'POST_PRUNE_FULL_DATA_CHECK_NOT_PROVEN')
            verify_provider_set(repo.list_snapshots(), records, selected)
        with factory.begin() as db:
            for record in records:
                if record.get('expired'):
                    db.get(SnapshotCopy, record['copy_id']).state = 'expired'
        round_state['retained_readbacks'] = [self.readback(selected, r, phase) for r in records
                                           if r['repository_id'] == selected['id'] and not r.get('expired')]
        round_state['complete'] = True
        self.save()

    def execute(self):
        from vaultrewind.server.db import Base, make_engine, sessions
        from vaultrewind.storage.credentials import credential_context
        from vaultrewind.storage.layout import new_repository_password
        with self.exclusive_destination():
            original, metadata = self.verify_prior_roundtrip()
            self.check_fresh_identities()
            self.check_absent_provider_prefixes()
            self.passwords = {r['id']: new_repository_password() for r in self.state['repositories']}
            self.secret_values.extend(self.passwords.values())
            self.state['encrypted_repository_secrets'] = self.box.encrypt(self.passwords,
                context=credential_context('retention-' + self.args.run_id))
            self.save()
            for selected in self.state['repositories']:
                self.state['current_action'] = {'operation': 'initialize', 'repository_id': selected['id']}
                self.save()
                with self.repository(selected) as repo:
                    initialized = repo.initialize()
                    require(initialized.get('created') is True, 'EXISTING_REPOSITORY_NEVER_ACCEPTED')
                    selected['restic_repository_id'] = initialized['repository_id']
                    repo.config.expected_repository_id = initialized['repository_id']
                    self.save()
                    require(not repo.list_snapshots(), 'NEW_REPOSITORY_NOT_EMPTY')
                    for record in self.state['records']:
                        if record['repository_id'] != selected['id']:
                            continue
                        tree = self.prepare_tree(original, metadata, record)
                        self.state['current_action'] = {'operation': 'commit', 'copy_id': record['copy_id']}
                        self.save()
                        self.guard()
                        committed = repo.commit(tree, record['snapshot_id'], record['captured_at'])
                        require(committed.get('stored_copy_verified') and
                                committed['manifest_hash'] == record['manifest_hash'], 'FIXTURE_COMMIT_NOT_PROVEN')
                        record['restic_snapshot_id'] = committed['restic_snapshot_id']
                        self.save()
                    verify_provider_set(repo.list_snapshots(), self.state['records'], selected)
            catalog = make_engine('sqlite:///' + str(self.root / 'fixture-catalog.sqlite3'))
            Base.metadata.create_all(catalog)
            factory = sessions(catalog)
            seed_catalog(factory, self.state['repositories'], self.state['records'], self.args.destination_id)
            sentinel = self.state['repositories'][1]
            other = next(r for r in self.state['records'] if r['label'] == 'other_instance')
            self.state['other_instance_before'] = self.readback(sentinel, other, 'sentinel-before')
            self.expire(factory, self.args.planner_time, {'expired'}, 'rolling-boundary')
            # A second explicit fixture time expires all unprotected points, including the cutoff point.
            # The newest complete point is now old too; only its actual planner protection keeps it.
            self.expire(factory, self.args.planner_time + timedelta(days=DAYS + 1),
                        {'boundary', 'within_one', 'within_two'}, 'newest-and-pin')
            with self.repository(sentinel) as repo:
                repo.describe()
                verify_provider_set(repo.list_snapshots(), self.state['records'], sentinel)
            self.state['other_instance_after'] = self.readback(sentinel, other, 'sentinel-after')
            require(self.state['other_instance_before'] == self.state['other_instance_after'],
                    'OTHER_INSTANCE_CHANGED')
            self.guard()
            catalog.dispose()
        # All provider sessions have exited and credential persistence has succeeded before publication.
        self.state['status'] = 'live_retention_proven'
        self.state['current_action'] = None
        self.save()
        self.publish()

    def publish(self):
        require(self.state['status'] == 'live_retention_proven' and len(self.state['rounds']) == 2 and
                all(r.get('complete') for r in self.state['rounds']), 'NO_UNEXECUTED_SUCCESS_REPORT')
        report = {k: self.state[k] for k in ('run_id', 'destination_id', 'planner_time', 'rounds',
                  'input_snapshot_id', 'input_manifest_hash', 'configuration_sha256',
                  'other_instance_before', 'other_instance_after')}
        report.update(version=1, provider='google_drive', result='live_retention_proven',
                      retention_live_proven=True, AC14_release_verified=False,
                      dedicated_test_account_acknowledged=True, synthetic_fixture_capture_times_only=True,
                      recorded_at=datetime.now(UTC).isoformat(),
                      evidence_boundary='direct_product_planner_and_provider_adapter_not_API_or_SSH_production_workflow',
                      native_catalog_snapshots_changed=False, native_controller_clock_changed=False,
                      actual_google_quota_tested=False, google_revocation_tested=False,
                      application_started=False, user_login_tested=False,
                      workspace_retained=True, automatic_resume_supported=False,
                      note='Separate recovery authorization/refresh/restore/reconnect/revocation evidence is required.')
        payload = json.dumps(report, indent=2) + '\n'
        require(all(s not in payload for s in self.secret_values if len(s) >= 8), 'PUBLIC_EVIDENCE_SECRET_DETECTED')
        path = PROJECT / 'docs/evidence/drive-retention.json'
        require(not path.exists() and not path.is_symlink(), 'EXISTING_EVIDENCE_REQUIRES_ROOT_REVIEW')
        from vaultrewind.security.privatefiles import write_private_file
        write_private_file(path, payload)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--root-go', default='')
    parser.add_argument('--dedicated-test-account', action='store_true')
    parser.add_argument('--destination-id', type=identifier)
    parser.add_argument('--run-id', type=identifier, help='Exact earlier recovery-drill run UUID.')
    parser.add_argument('--planner-time', type=planner_time, help='Explicit future UTC test time, e.g. 2040-01-31T12:00:00Z.')
    parser.add_argument('--credential-state-dir', type=Path,
                        help='Only the verified native worker provider_credential_state_dir, if explicitly configured.')
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    if not args.execute:
        print(json.dumps({'status': 'prepared_not_run_drive_parked', 'retention_live_proven': False,
                          'AC14_release_verified': False, 'requires': [RELEASE, 'dedicated authorized destination UUID',
                          'matched prior recovery run UUID and verified private bytes', 'explicit future fixture UTC time'],
                          'network_sql_provider_ssh_docker_calls': 0, 'private_files_opened': 0,
                          'evidence_written': False}), flush=True)
        return 0
    drill = None
    try:
        require_execution(args)  # Invalid flag combinations have no side effects, even umask changes.
        os.umask(0o077)
        drill = RetentionDrill(args)
        drill.execute()
    except Exception as error:  # noqa: BLE001 - never expose private values or provider exception details.
        code = str(error) if isinstance(error, DrillError) else 'RETENTION_DRILL_FAILED_PRIVATE_DETAILS_WITHHELD'
        if not re.fullmatch(r'[A-Z0-9_]{1,160}', code):
            code = 'RETENTION_DRILL_FAILED_PRIVATE_DETAILS_WITHHELD'
        if drill is not None:
            drill.state.update(status='needs_attention', error_code=code, workspace_retained=True)
            try:
                drill.save()
            except Exception:  # noqa: BLE001 - private exception details must stay withheld.
                print('CHECKPOINT_SAVE_FAILED_KEEP_ALL_PRIVATE_RECOVERY_STATE', flush=True)
        print(code, flush=True)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

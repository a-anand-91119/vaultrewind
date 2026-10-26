"""Apply narrowly supported root-approved substitutions only to private generations."""
from __future__ import annotations

import os
import stat
from pathlib import Path
from urllib.parse import urlsplit

from vaultrewind.core.errors import VaultRewindError

from .journal import atomic_json
from .policy import no_symlink
from .protocol import decode, fail


def approved_environment(profile):
    environment = profile.get('environment', {})
    if not isinstance(environment, dict) or set(environment) - {'DOMAIN'}:
        fail('TARGET_OVERLAY_UNSUPPORTED', 'Only the DOMAIN environment substitution is supported; enroll other configuration changes through a reviewed deployment profile.')
    if 'DOMAIN' not in environment:
        return {}
    domain = environment['DOMAIN']
    try:
        if not isinstance(domain, str) or len(domain) > 2048 or any(ord(c) <= 32 for c in domain):
            raise ValueError
        url = urlsplit(domain)
        if url.scheme not in ('http', 'https') or not url.hostname or url.username or url.password or url.query or url.fragment:
            raise ValueError
        if url.port is not None and not 1 <= url.port <= 65535:
            raise ValueError
    except ValueError:
        fail('TARGET_OVERLAY_UNSUPPORTED', 'The approved DOMAIN must be a valid HTTP(S) base URL without credentials, query or fragment.')
    return {'DOMAIN': domain.rstrip('/')}


def config_path(mounts):
    return Path(next(m['source'] for m in mounts if m['snapshot_path'] == 'data')) / 'config.json'


def config_value(path):
    no_symlink(path, missing_leaf=True)
    if not path.exists():
        return {}
    if not path.is_file():
        fail('TARGET_CONFIG_INVALID', 'Restored application configuration must be a regular JSON file.')
    try:
        with path.open('rb') as stream:
            return decode(stream.read(1024 * 1024 + 1))
    except VaultRewindError:
        fail('TARGET_CONFIG_INVALID', 'Restored application configuration is invalid or exceeds its supported bound.')


def apply_environment(mounts, environment):
    if not environment:
        return
    path = config_path(mounts)
    config = config_value(path)
    previous = path.stat() if path.exists() else None
    xattrs = {key: os.getxattr(path, key) for key in os.listxattr(path)} if previous else {}
    # Vaultwarden config.json takes precedence over DOMAIN in the environment.
    config['domain'] = environment['DOMAIN']
    atomic_json(path, config)
    if previous:
        os.chown(path, previous.st_uid, previous.st_gid)
        os.chmod(path, stat.S_IMODE(previous.st_mode))
        for key, value in xattrs.items():
            os.setxattr(path, key, value)
    with path.open('rb') as stream:
        os.fsync(stream.fileno())
    verify_environment(mounts, environment)


def verify_environment(mounts, environment):
    if not environment:
        return
    if config_value(config_path(mounts)).get('domain') != environment['DOMAIN']:
        fail('TARGET_CONFIG_MISMATCH', 'The restored effective application URL differs from its approved target overlay; re-stage the restore.')

#!/usr/bin/env python3
"""Opt-in real encrypted-client recovery proof; default preparation has no I/O.

Only UUID-scoped, newly created local fixtures are mutation targets. No secrets
are accepted as command arguments or emitted. Stop at plan for parent review;
activation and proof are separate resumable stages. Failed attempts are retained.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import socket
import ssl
import stat
import subprocess
import sys
import time
import urllib.request
import zipfile
from pathlib import Path
from uuid import UUID, uuid4

PROJECT = Path(__file__).resolve().parents[1]
PRIVATE = PROJECT / '.runtime/controller'
RUNTIME = PROJECT / '.runtime/authenticated-recovery'
SOURCE_ID = '46ac8eb9-1854-4fc6-924f-af14c6b7d0c2'
FORBIDDEN_IDS = {SOURCE_ID, 'b05f7958-3d3b-48d6-a8f2-8eb900533149',
                 '927a1917-9de6-4777-b28f-aedb1c6c1816'}
DESTINATION = 'c59b1b7c-810e-4ebe-a7bf-d5d559891f1d'
ORIGIN = 'http://127.0.0.1:8098'
HELPER = 'cbf84b999eab462a6ad08b86ef06c631c148e796d242459f227c79df2a0a0093'
IMAGE = 'ghcr.io/dani-garcia/vaultwarden@sha256:efb3cde962015fcc036b2ea625242248611943b27212ebf4392841fb30fad055'
CLI_VERSION = '2026.9.0'
CLI_ARCHIVE_SHA256 = '580c1deec8345b19dbac7f8b02babb6cc4fe250c69c567e29061f727f1e40768'
CLI_URL = f'https://github.com/bitwarden/clients/releases/download/cli-v{CLI_VERSION}/bw-linux-{CLI_VERSION}.zip'
CLIENT_ORIGIN = 'https://127.0.0.1:18443'
SOURCES = [
    'https://bitwarden.com/help/cli/',
    'https://github.com/bitwarden/clients/releases/tag/cli-v2026.9.0',
    'https://api.github.com/repos/bitwarden/clients/releases/tags/cli-v2026.9.0',
    'https://github.com/dani-garcia/vaultwarden/releases/tag/1.37.4',
    'https://raw.githubusercontent.com/bitwarden/clients/cli-v2026.9.0/apps/cli/src/bw.ts',
    'https://raw.githubusercontent.com/bitwarden/clients/cli-v2026.9.0/apps/cli/src/vault.program.ts',
    'https://raw.githubusercontent.com/bitwarden/clients/cli-v2026.9.0/apps/cli/src/utils.ts',
    'https://raw.githubusercontent.com/bitwarden/clients/cli-v2026.9.0/apps/cli/src/vault/create.command.ts',
    'https://raw.githubusercontent.com/bitwarden/clients/cli-v2026.9.0/apps/cli/src/commands/edit.command.ts',
    'https://raw.githubusercontent.com/bitwarden/clients/cli-v2026.9.0/apps/cli/src/program.ts',
    'https://raw.githubusercontent.com/bitwarden/clients/cli-v2026.9.0/apps/cli/src/auth/commands/login.command.ts',
]
ACTIVE = {'queued', 'running', 'waiting_retry', 'cancel_requested'}
TERMINAL = {'succeeded', 'failed', 'partial', 'cancelled', 'rolled_back', 'rollback_failed', 'needs_attention'}


class DrillError(Exception):
    """Public error codes only; never forward tool exceptions/output."""


def require(value, code):
    if not value:
        raise DrillError(code)


def identifier(value):
    try:
        require(str(UUID(value)) == value and UUID(value).version == 4 and value not in FORBIDDEN_IDS,
                'NEW_CANONICAL_UUID4_REQUIRED')
    except (ValueError, TypeError, AttributeError):
        raise DrillError('NEW_CANONICAL_UUID4_REQUIRED') from None
    return value


def digest(value):
    raw = value if isinstance(value, bytes) else json.dumps(value, sort_keys=True, separators=(',', ':'),
                                                          default=str).encode()
    return hashlib.sha256(raw).hexdigest()


def no_symlinks(path):
    require(path.is_absolute() and all(not p.is_symlink() for p in (path, *path.parents)),
            'SYMLINK_PATH_REJECTED')


def private_read(path):
    no_symlinks(path)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o077,
                'PRIVATE_INPUT_REQUIRED')
        return stream.read()


def private_write(path, value):
    no_symlinks(path)
    raw = value if isinstance(value, bytes) else json.dumps(value, indent=2, default=str).encode()
    temporary = path.with_name(path.name + '.tmp-' + uuid4().hex)
    with os.fdopen(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'wb') as out:
        out.write(raw)
        out.flush()
        os.fsync(out.fileno())
    os.replace(temporary, path)


def run(args, *, payload=None, env=None, timeout=180):
    result = subprocess.run(args, input=payload, env=env, capture_output=True, check=False, timeout=timeout)
    require(result.returncode == 0, 'PRIVATE_COMMAND_FAILED')
    return result.stdout


def client_environment(appdata):
    """Used by version probes as well as authenticated commands; never inherit HOME."""
    no_symlinks(appdata)
    environment = {k: v for k, v in os.environ.items() if k in {'PATH', 'LANG', 'LC_ALL', 'TMPDIR'}}
    environment.update(BITWARDENCLI_APPDATA_DIR=str(appdata), BW_NOINTERACTION='true',
                       BW_DISABLE_UPDATE_CHECK='true')
    return environment


def scope(run_id, instance_id):
    identifier(run_id)
    identifier(instance_id)
    require(run_id != instance_id, 'DISTINCT_RUN_AND_INSTANCE_REQUIRED')
    return {'root': RUNTIME / run_id, 'name': 'vrw-auth-drill-' + instance_id,
            'network': 'vrw-auth-drill-' + run_id, 'label': 'authenticated-recovery:' + run_id}


def validate_container(value, state, paths):
    labels = value['Config'].get('Labels') or {}
    restore_job = state.get('steps', {}).get('restore', {}).get('job_id')
    ownership = labels.get('vaultrewind.authenticated-recovery') == state['run_id'] or (
        restore_job is not None and labels.get('org.vaultrewind.operation') == restore_job and
        labels.get('org.vaultrewind.role') == 'active')
    require(ownership and
            labels.get('org.vaultrewind.instance') == state['instance_id'] and
            value['Name'] == '/' + paths['name'], 'OWNED_FIXTURE_LABEL_REQUIRED')
    mounts = value['Mounts']
    require(len(mounts) == 1 and mounts[0]['Type'] == 'bind' and mounts[0]['Source'] == str(paths['root'] / 'data')
            and mounts[0]['Destination'] == '/data' and mounts[0]['RW'], 'OWNED_FIXTURE_MOUNT_REQUIRED')
    require(value['Image'] == state['image_id'] and
            value['HostConfig']['PortBindings'] == {'80/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '18280'}]} and
            value['HostConfig']['NetworkMode'] == paths['network'], 'OWNED_FIXTURE_BINDING_REQUIRED')


def preserved_policy(before, after, new_id):
    require(new_id not in before['instances'] and set(after['instances']) == set(before['instances']) | {new_id}
            and all(after['instances'][key] == val for key, val in before['instances'].items())
            and {k: v for k, v in before.items() if k != 'instances'} ==
                {k: v for k, v in after.items() if k != 'instances'}, 'EXISTING_POLICY_CHANGED')


def exact_job(rows, key, request_hash=None):
    matches = [row for row in rows if row['idempotency_key'] == key]
    require(len(matches) <= 1, 'AMBIGUOUS_JOB_IDENTITY')
    if matches and request_hash:
        require(matches[0]['request_hash'] == request_hash, 'RECONCILE_REQUEST_CHANGED')
    return matches[0]['id'] if matches else None


def safe_failures(state):
    identifier(state['run_id'])
    result = []
    for entry in state.get('failures', []):
        require(isinstance(entry.get('code'), str) and re.fullmatch(r'[A-Z_0-9]+', entry['code']) and
                entry.get('stage') in {'plan', 'activate', 'prove'} and type(entry.get('time')) is int,
                'FAILURE_HISTORY_SECRET_BOUNDARY')
        result.append({'run_id': state['run_id'], 'stage': entry['stage'],
                       'code': entry['code'], 'unix_time': entry['time']})
    return result


def browser_registration_program():
    # Credentials are read from stdin. No Playwright reports, screenshots, trace,
    # video, storage-state export or console/network event logging are installed.
    return r'''
const fs = require('fs');
const { chromium } = require('./frontend/node_modules/playwright');
(async () => {
  const v = JSON.parse(fs.readFileSync(0, 'utf8'));
  if (v.origin !== 'https://127.0.0.1:18443') throw Error('SCOPE');
  const browser = await chromium.launch({headless:true, chromiumSandbox:false,
    args:['--ignore-certificate-errors-spki-list='+v.spki]});
  let stage='context', page;
  try {
    const context = await browser.newContext({acceptDownloads:false, serviceWorkers:'block'});
    await context.route('**/*', route => {
      const u = new URL(route.request().url());
      return (u.origin === v.origin || u.protocol === 'data:') ? route.continue() : route.abort();
    });
    page = await context.newPage(); stage='navigate';
    await page.goto(v.origin + '/#/register', {waitUntil:'domcontentloaded',timeout:60000});
    // Only safe structural information is returned on a failed first attempt.
    const fill = async (selector,value) => { await page.locator(selector).first().fill(value); };
    stage='email'; await page.locator('input[type=email]').first().waitFor({timeout:60000});
    await fill('input[type=email]',v.email);
    const names=page.locator('input[formcontrolname=name],input[name=name]');
    if (await names.count()) await names.first().fill(v.name);
    if(!await page.locator('input[type=password]').count()) {
      stage='continue';
      await page.getByRole('button',{name:/continue/i}).click();
    }
    stage='password';
    const passwords = page.locator('input[type=password]');
    await passwords.first().waitFor({timeout:30000});
    await passwords.nth(0).fill(v.password); await passwords.nth(1).fill(v.password);
    stage='checkbox'; const checkbox=page.locator('input[type=checkbox]');
    for(let i=0;i<await checkbox.count();i++) {
      const item=checkbox.nth(i);
      if(await item.getAttribute('formcontrolname')==='checkForBreaches') await item.uncheck();
      else if(await item.getAttribute('required')!==null) await item.check();
    }
    const accepted=page.waitForResponse(r=>r.status()===200 && r.request().method()==='POST' &&
      /\/accounts\/register\/finish$/.test(new URL(r.url()).pathname),{timeout:60000});
    stage='submit'; await page.getByRole('button',{name:/create account|submit/i}).click();
    const confirm=page.getByRole('button',{name:/yes|confirm/i});
    try {await confirm.first().click({timeout:2000});} catch {}
    stage='account-response'; await accepted;
    // DOM and URL stay private and contain no exported credentials.
    const safe={registered:true,official_registration_finish_200:true};
    fs.writeFileSync(v.result,JSON.stringify(safe),{mode:0o600});
    if(!safe.registered) process.exitCode=3;
  } catch {
    const safe={registered:false,stage,inputs:page?await page.locator('input').evaluateAll(es=>es.map(e=>({type:e.type,form:e.getAttribute('formcontrolname')}))):[]};
    if(page) {
      const text=await page.locator('body').textContent();
      safe.flags={hasCreateAccount:/create account/i.test(text),hasContinue:/continue/i.test(text),hasCheckEmail:/check your email/i.test(text),hasPassword:/master password/i.test(text)};
    }
    fs.writeFileSync(v.result,JSON.stringify(safe),{mode:0o600}); process.exitCode=3;
  } finally {await browser.close();}
})().catch(()=>{process.exitCode=2;});
'''


class Drill:
    def __init__(self, run_id):
        identifier(run_id)
        os.umask(0o077)
        self.root = RUNTIME / run_id
        no_symlinks(self.root)
        self.root.mkdir(parents=True, mode=0o700, exist_ok=True)
        require(not self.root.stat().st_mode & 0o077, 'PRIVATE_RUNTIME_REQUIRED')
        self.checkpoint = self.root / 'checkpoint.json'
        self.state = json.loads(private_read(self.checkpoint)) if self.checkpoint.exists() else {
            'run_id': run_id, 'instance_id': str(uuid4()), 'steps': {}, 'failures': []}
        require(self.state['run_id'] == run_id, 'CHECKPOINT_RUN_MISMATCH')
        self.paths = scope(run_id, self.state['instance_id'])
        self.instance = self.state['instance_id']
        self.save()

    def save(self):
        private_write(self.checkpoint, self.state)

    def connect(self):
        import httpx

        from vaultrewind.server.adapters import Adapters
        from vaultrewind.server.db import make_engine, sessions
        from vaultrewind.server.models import Host, Instance
        from vaultrewind.server.settings import Settings
        self.settings = Settings(database_url=private_read(PRIVATE / 'database-url').decode().strip(),
            master_key_file=PRIVATE / 'master', bootstrap_secret_file=PRIVATE / 'bootstrap',
            local_storage_root=Path('/srv/vaultrewind-native-controller/backups'),
            staging_dir=Path('/srv/vaultrewind-native-controller/staging'), public_origin=ORIGIN, secure_cookies=False)
        self.engine = make_engine(self.settings.database_url)
        require(self.engine.url.host in {None, 'localhost', '127.0.0.1'} and
                self.engine.url.get_backend_name() == 'postgresql', 'LOCAL_CONTROLLER_REQUIRED')
        self.sessions = sessions(self.engine)
        self.adapters = Adapters(self.settings, self.sessions)
        with self.sessions() as db:
            source = db.get(Instance, SOURCE_ID)
            host = db.get(Host, source.host_id)
            require(host.endpoint == '127.0.0.1' and host.port == 22, 'EXACT_NATIVE_LOOPBACK_HOST_REQUIRED')
            self.host_id = host.id
        cookies = json.loads(private_read(PRIVATE / 'api-cookies.json'))
        self.api = httpx.Client(base_url=ORIGIN, cookies=cookies, trust_env=False, timeout=30,
            follow_redirects=False, headers={'Origin': ORIGIN, 'X-CSRF-Token': cookies['vr_csrf']})

    def request(self, method, path, body=None, *, expected=200, key=None, headers=None):
        selected = dict(headers or {})
        if method != 'GET':
            selected['Idempotency-Key'] = key or ('auth-drill-' + self.state['run_id'] + '-' + digest([path, body])[:24])
        response = self.api.request(method, '/api/v1' + path, json=body, headers=selected)
        if response.status_code != expected:
            raise DrillError('NATIVE_HTTP_' + str(response.status_code))
        return response.json()

    def idle(self):
        from sqlalchemy import select

        from vaultrewind.server.models import Job
        with self.sessions() as db:
            require(not list(db.scalars(select(Job.id).where(Job.state.in_(ACTIVE)))), 'ACTIVE_JOBS_BLOCK_MUTATION')
        require(not self.discovered()['pending_operations'], 'PENDING_JOURNALS_BLOCK_MUTATION')

    def discovered(self):
        from vaultrewind.server.provisioning import Provisioner
        return Provisioner(self.adapters).admin_request(self.host_id, {'mode': 'discover'})

    def journals(self):
        return {p.stem: digest(p.read_bytes()) for p in Path('/var/lib/vaultrewind-helper/journals').glob('*.json')}

    def helper(self):
        require(digest((PROJECT / '.runtime/helper-bundle/helper.pyz').read_bytes()) == HELPER and
                digest(Path('/opt/vaultrewind-helper', HELPER, 'helper.pyz').read_bytes()) == HELPER,
                'FROZEN_HELPER_CHANGED')

    def wait_job(self, ident):
        deadline = time.monotonic() + 1500
        while time.monotonic() < deadline:
            job = self.request('GET', '/jobs/' + ident)
            if job['state'] in TERMINAL:
                require(job['state'] == 'succeeded', 'JOB_' + job['state'].upper())
                return job
            time.sleep(2)
        raise DrillError('EXACT_JOB_STILL_PENDING')

    def job(self, stage, path, body):
        from sqlalchemy import select

        from vaultrewind.server.models import Job
        key = 'auth-drill-' + self.state['run_id'] + '-' + stage
        state = self.state['steps'].setdefault(stage, {'key': key, 'path': path, 'body_sha256': digest(body)})
        require(state['path'] == path and state['body_sha256'] == digest(body), 'CHECKPOINT_REQUEST_CHANGED')
        self.save()
        if not state.get('job_id'):
            with self.sessions() as db:
                rows = list(db.scalars(select(Job).where(Job.idempotency_key == key)))
                matched = exact_job([{'id': row.id, 'idempotency_key': row.idempotency_key,
                                      'request_hash': row.request_hash} for row in rows], key,
                                    state.get('native_request_hash'))
                if rows:
                    expected_kind = {'plan': 'activation_plan', 'activate': 'activate', 'discover': 'discover',
                                     'backup': 'backup', 'restore': 'restore'}[stage]
                    require(rows[0].instance_id == (self.instance if stage in {'backup', 'restore'} else None)
                            and rows[0].kind == expected_kind, 'JOB_SCOPE_MISMATCH')
                    state['job_id'] = matched
                    state['native_request_hash'] = rows[0].request_hash
            if not state.get('job_id'):
                require(not state.get('attempted'), 'LOST_JOB_RESPONSE_REQUIRES_EXACT_RECONCILE')
                state['attempted'] = True
                self.save()
                state['job_id'] = self.request('POST', path, body, expected=202, key=key)['job_id']
            self.save()
        result = self.wait_job(state['job_id'])
        require(result['id'] == state['job_id'] and result.get('instance_id') ==
                (self.instance if stage in {'backup', 'restore'} else None), 'JOB_RESULT_SCOPE_MISMATCH')
        state['succeeded'] = True
        self.save()
        return result

    def inspect(self):
        value = json.loads(run(['docker', 'inspect', self.paths['name']]))[0]
        validate_container(value, self.state, self.paths)
        no_symlinks(self.root / 'data')
        return value

    def tls(self):
        """Private test TLS termination; all upstream response bytes are unchanged."""
        self.inspect()
        certificate, key = self.root / 'fixture-cert.pem', self.root / 'fixture-key.pem'
        if not certificate.exists():
            require(not key.exists(), 'PARTIAL_TLS_IDENTITY_REQUIRES_DIAGNOSIS')
            run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-noenc', '-days', '2',
                '-keyout', str(key), '-out', str(certificate), '-subj', '/CN=127.0.0.1',
                '-addext', 'subjectAltName=IP:127.0.0.1'])
        private_read(key)
        private_read(certificate)
        pubkey = run(['openssl', 'x509', '-in', str(certificate), '-pubkey', '-noout'])
        der = run(['openssl', 'pkey', '-pubin', '-outform', 'DER'], payload=pubkey)
        self.state['tls_spki'] = base64.b64encode(hashlib.sha256(der).digest()).decode()
        self.state['tls_certificate_sha256'] = digest(private_read(certificate))
        self.save()
        import httpx
        context = ssl.create_default_context(cafile=str(certificate))
        def healthy():
            try:
                with httpx.Client(verify=context, trust_env=False, timeout=3) as client:
                    return client.get(CLIENT_ORIGIN + '/alive').status_code == 200
            except (httpx.TransportError, OSError):
                return False
        if not healthy():
            with socket.socket() as probe:
                probe.bind(('127.0.0.1', 18443))
            child = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), '--serve-tls',
                '--run-id', self.state['run_id']], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, start_new_session=True)
            self.state.setdefault('tls_process_ids', []).append(child.pid)
            self.save()
            for _ in range(30):
                if healthy():
                    break
                require(child.poll() is None, 'PRIVATE_TLS_PROXY_FAILED')
                time.sleep(0.5)
            else:
                raise DrillError('PRIVATE_TLS_PROXY_NOT_READY')

    def tools(self):
        target = self.root / 'tools'
        target.mkdir(mode=0o700, exist_ok=True)
        archive = target / 'bw.zip'
        if not archive.exists():
            with urllib.request.urlopen(CLI_URL, timeout=60) as src:
                private_write(archive, src.read(60 * 1024**2))
        require(digest(private_read(archive)) == CLI_ARCHIVE_SHA256, 'CLI_ARCHIVE_INTEGRITY_FAILED')
        if not (target / 'bw').exists():
            with zipfile.ZipFile(archive) as bundle:
                private_write(target / 'bw', bundle.read('bw'))
            (target / 'bw').chmod(0o700)
        with zipfile.ZipFile(archive) as bundle:
            require(digest(private_read(target / 'bw')) == digest(bundle.read('bw')), 'CLI_BINARY_CHANGED')
        version_data = target / 'version-appdata'
        version_data.mkdir(mode=0o700, exist_ok=True)
        require(run([str(target / 'bw'), '--version'], env=client_environment(version_data)).decode().strip()
                == CLI_VERSION, 'PINNED_CLI_VERSION_REQUIRED')
        witnesses = []
        for index, url in enumerate(SOURCES):
            path = target / ('official-source-' + str(index))
            if not path.exists():
                with urllib.request.urlopen(url, timeout=60) as src:
                    private_write(path, src.read(8 * 1024**2))
            witnesses.append({'url': url, 'sha256': digest(private_read(path))})
        sources = [private_read(target / ('official-source-' + str(i))).decode() for i in (5, 6, 7, 8)]
        require('Can also be piped into stdin' in sources[0] and 'process.stdin' in sources[1] and
                all('CliUtils.readStdin()' in value for value in sources[2:]),
                'CLI_STDIN_SOURCE_MUST_BE_REVIEWED')
        self.state['tools'] = {'version': CLI_VERSION, 'archive_sha256': CLI_ARCHIVE_SHA256,
                               'binary_sha256': digest(private_read(target / 'bw')), 'sources': witnesses}
        self.save()

    def fixture(self):
        if self.state.get('fixture_ready'):
            self.inspect()
            return
        self.idle()
        self.helper()
        if 'baseline' not in self.state:
            before = self.discovered()
            self.state['baseline'] = {'policy': before['installed_policy'], 'journals': self.journals(),
                                      'others': self.other_witness()}
            require(self.instance not in before['installed_policy']['instances'], 'INSTANCE_ALREADY_EXISTS')
            self.save()
        if not (self.root / 'credentials.json').exists():
            private_write(self.root / 'credentials.json', {'email': secrets.token_hex(16) + '@example.invalid',
                'password': secrets.token_urlsafe(48), 'name': secrets.token_urlsafe(18),
                'item_name': secrets.token_urlsafe(20), 'username': secrets.token_urlsafe(24),
                'login_password': secrets.token_urlsafe(40), 'changed_password': secrets.token_urlsafe(40),
                'marker_name': secrets.token_urlsafe(20)})
            private_write(self.root / 'attachment.bin', secrets.token_bytes(65536))
        (self.root / 'data').mkdir(mode=0o700, exist_ok=True)
        if not self.state.get('image_id'):
            image = json.loads(run(['docker', 'image', 'inspect', IMAGE]))[0]
            self.state['image_id'] = image['Id']
            self.save()
        if not self.state.get('network_created'):
            require(not self.state.get('network_attempted'), 'NETWORK_CREATE_RESPONSE_UNRESOLVED')
            self.state['network_attempted'] = True
            self.save()
            run(['docker', 'network', 'create', '--driver', 'bridge', '--label',
                 'vaultrewind.authenticated-recovery=' + self.state['run_id'], self.paths['network']])
            self.state['network_created'] = True
            self.save()
        if not self.state.get('container_created'):
            with socket.socket() as probe:
                probe.bind(('127.0.0.1', 18280))
            require(not self.state.get('container_attempted'), 'CONTAINER_CREATE_RESPONSE_UNRESOLVED')
            self.state['container_attempted'] = True
            self.save()
            run(['docker', 'run', '-d', '--pull=never', '--name', self.paths['name'],
                 '--label', 'vaultrewind.fixture=true', '--label', 'vaultrewind.authenticated-recovery=' + self.state['run_id'],
                 '--label', 'org.vaultrewind.instance=' + self.instance, '--network', self.paths['network'],
                 '-p', '127.0.0.1:18280:80', '--mount', f'type=bind,source={self.root / "data"},target=/data',
                 '-e', 'DOMAIN=http://127.0.0.1:18280', '-e', 'SIGNUPS_ALLOWED=true', '-e', 'SIGNUPS_VERIFY=false',
                 '-e', 'PUSH_ENABLED=false', '-e', 'DISABLE_ICON_DOWNLOAD=true', '-e', 'LOG_LEVEL=off', IMAGE])
            self.state['container_created'] = True
            self.save()
        self.inspect()
        import httpx
        with httpx.Client(trust_env=False, timeout=5) as public:
            for _ in range(90):
                try:
                    if public.get('http://127.0.0.1:18280/alive').status_code == 200:
                        break
                except httpx.TransportError:
                    pass
                time.sleep(1)
            else:
                raise DrillError('NEW_FIXTURE_STARTUP_FAILED')
        network = json.loads(run(['docker', 'network', 'inspect', self.paths['network']]))[0]
        require(network['Driver'] == 'bridge' and network['Labels'].get('vaultrewind.authenticated-recovery') ==
                self.state['run_id'], 'DEDICATED_FIXTURE_NETWORK_REQUIRED')
        self.state['fixture_ready'] = True
        self.save()

    def other_witness(self):
        from sqlalchemy import select

        from vaultrewind.server.models import (
            BackupPolicy,
            Instance,
            PolicyDestination,
            Snapshot,
            SnapshotCopy,
        )
        def rows(db, model, predicate=None, omit=()):
            query = select(model)
            if predicate is not None:
                query = query.where(predicate)
            return sorted([{c.name: getattr(r, c.name) for c in model.__table__.columns if c.name not in omit}
                           for r in db.scalars(query)], key=lambda x: str(x))
        with self.sessions() as db:
            # Activation legitimately advances revisions and reseals configuration.
            policies = rows(db, BackupPolicy, BackupPolicy.instance_id != self.instance, ('revision', 'updated_at'))
            ids = [p['id'] for p in policies]
            points = rows(db, Snapshot, Snapshot.instance_id != self.instance)
            configurations = {item.id: self.adapters.secrets.get(db, item.configuration_secret_id)
                              for item in db.scalars(select(Instance).where(Instance.id != self.instance))}
            return {'instances': digest(rows(db, Instance, Instance.id != self.instance,
                        ('revision', 'updated_at', 'configuration_secret_id'))), 'policies': digest(policies),
                    'instance_configurations': digest(configurations),
                    'controller_master': digest(private_read(PRIVATE / 'master')),
                    'policy_destinations': digest(rows(db, PolicyDestination, PolicyDestination.policy_id.in_(ids))),
                    'snapshots': digest(points), 'copies': digest(rows(db, SnapshotCopy,
                        SnapshotCopy.snapshot_id.in_([p['id'] for p in points]))),
                    'containers': digest([{k: v for k, v in {
                        'id': item['Id'], 'image': item['Image'], 'config': item['Config'],
                        'mounts': item['Mounts'], 'started_at': item['State']['StartedAt'],
                        'running': item['State']['Running']}.items()} for item in json.loads(run(
                        ['docker', 'inspect', *[r.container_id for r in db.scalars(select(Instance).where(
                            Instance.id != self.instance, Instance.host_id == self.host_id)) if r.container_id]]))])}

    def plan(self):
        self.tools()
        self.fixture()
        self.idle()
        self.helper()
        if self.state.get('activation_plan'):
            return
        before = self.state['baseline']['policy']
        require(self.discovered()['installed_policy'] == before, 'SHARED_POLICY_CHANGED_BEFORE_PLAN')
        profile = {'revision': 1, 'container_id': self.inspect()['Id'], 'container_name': self.paths['name'],
            'mounts': [{'type': 'bind', 'source': str(self.root / 'data'), 'target': '/data',
                        'read_only': False, 'snapshot_path': 'data'}],
            'allowed_operations': ['discover', 'preflight', 'capture', 'export', 'stage_restore', 'commit_restore',
                                    'rollback', 'status', 'cancel', 'cleanup'],
            'allowed_image_ids': [self.state['image_id']], 'allowed_networks': [self.paths['network']],
            'port_bindings': {'80/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '18280'}]},
            'additional_files': {}, 'dependency_inventory': [], 'external_dependencies_ready': True,
            'ownership': 'exclusive', 'capture_budget': 300, 'restore_budget': 900, 'validation_window': 180,
            'max_archive_bytes': 2 * 1024**3, 'free_space_reserve': 256 * 1024**2,
            'recovery_profile': {'revision': 1, 'network': self.paths['network'],
                'port_bindings': {'80/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '18280'}]},
                'environment': {'DOMAIN': 'http://127.0.0.1:18280'}}}
        after = {**before, 'instances': {**before['instances'], self.instance: profile}}
        preserved_policy(before, after, self.instance)
        private_write(self.root / 'proposed-policy.json', after)
        job = self.job('plan', f'/hosts/{self.host_id}/activation-plans', {'policy': after})
        self.state['activation_plan'] = job['result']
        self.save()

    def activate(self, reviewed_plan):
        plan = self.state.get('activation_plan')
        require(plan and reviewed_plan == plan['plan_id'], 'EXACT_PARENT_REVIEWED_PLAN_REQUIRED')
        if not self.state.get('activated'):
            self.helper()
            if not self.state['steps'].get('activate', {}).get('attempted'):
                self.idle()
                require(self.discovered()['installed_policy'] == self.state['baseline']['policy'] and
                        self.journals() == self.state['baseline']['journals'], 'SHARED_BASELINE_CHANGED')
            self.job('activate', f'/hosts/{self.host_id}/activate',
                     {'plan_id': plan['plan_id'], 'plan_hash': plan['plan_hash']})
            self.state['activated'] = True
            self.save()
        installed = self.discovered()['installed_policy']
        preserved_policy(self.state['baseline']['policy'], installed, self.instance)
        require(installed == json.loads(private_read(self.root / 'proposed-policy.json')) and
                self.journals() == self.state['baseline']['journals'], 'ACTIVATION_PRESERVATION_FAILED')
        self.helper()
        self.enroll()

    def enroll(self):
        if self.state.get('enrolled'):
            return
        job = self.job('discover', f'/hosts/{self.host_id}/discover', {'instance_id': self.instance})
        enrollment = self.request('GET', '/jobs/' + job['id'] + '/enrollment')
        require(enrollment['ready'] and enrollment['restore_enabled'], 'NEW_PROFILE_NOT_READY')
        existing = self.api.get('/api/v1/instances/' + self.instance)
        if existing.status_code == 404:
            self.request('POST', '/instances', {'host_id': self.host_id, 'name': 'Authenticated recovery synthetic drill',
                'container_id': self.inspect()['Id'], 'configuration': enrollment['configuration']}, expected=201)
        else:
            require(existing.status_code == 200 and existing.json()['host_id'] == self.host_id,
                    'ENROLLMENT_RESPONSE_UNRESOLVED')
        policy = self.request('GET', f'/instances/{self.instance}/policy')
        self.request('PATCH', f'/instances/{self.instance}/policy',
            {'enabled': False, 'destinations': [{'destination_id': DESTINATION, 'required': True}]},
            headers={'If-Match': '"' + str(policy['revision']) + '"'})
        self.state['enrolled'] = True
        self.save()

    def cli(self, profile, *args, payload=None, session=None):
        # Every command uses a dedicated client appdata directory. Never assign HOME.
        require(re.fullmatch(r'[a-z]+-[0-9a-f]{32}', profile), 'NEW_CLI_PROFILE_REQUIRED')
        appdata = self.root / profile
        appdata.mkdir(mode=0o700, exist_ok=True)
        require('--session' not in args and not any(a.startswith('--session=') for a in args),
                'SESSION_ARGUMENT_REJECTED')
        if args and args[0] == 'config':
            require(args in {('config', 'server'), ('config', 'server', CLIENT_ORIGIN)},
                    'EXACT_NEW_BW_SERVER_REQUIRED')
        credentials = json.loads(private_read(self.root / 'credentials.json'))
        env = client_environment(appdata)
        env['VAULT_DRILL_PASSWORD'] = credentials['password']
        env['NODE_EXTRA_CA_CERTS'] = str(self.root / 'fixture-cert.pem')
        if args and args[0] == 'login':
            env['BW_NOINTERACTION'] = 'false'
        if session:
            env['BW_SESSION'] = session
        try:
            return run([str(self.root / 'tools/bw'), *args], payload=payload, env=env, timeout=180)
        except DrillError:
            verb = args[0].upper() if args and args[0] in {
                'config', 'login', 'unlock', 'lock', 'sync', 'status', 'get', 'create', 'edit', 'delete', 'list', 'logout'
            } else 'COMMAND'
            raise DrillError('CLI_' + verb + '_FAILED') from None

    def login(self, prefix):
        profile = prefix + '-' + uuid4().hex
        self.cli(profile, 'config', 'server', CLIENT_ORIGIN)
        configured = self.cli(profile, 'config', 'server').decode().strip()
        require(configured == CLIENT_ORIGIN, 'EXACT_NEW_BW_SERVER_REQUIRED')
        credentials = json.loads(private_read(self.root / 'credentials.json'))
        # The CLI prompts for the email on stdin; password comes from its documented env channel.
        session = self.cli(profile, 'login', '--passwordenv', 'VAULT_DRILL_PASSWORD', '--raw',
                           payload=(credentials['email'] + '\n').encode()).decode().strip()
        require(len(session) > 20 and '\n' not in session, 'CLI_LOGIN_SESSION_INVALID')
        self.cli(profile, 'lock', session=session)
        session = self.cli(profile, 'unlock', '--passwordenv', 'VAULT_DRILL_PASSWORD', '--raw').decode().strip()
        require(len(session) > 20 and '\n' not in session, 'CLI_UNLOCK_SESSION_INVALID')
        self.cli(profile, 'sync', session=session)
        status = json.loads(self.cli(profile, 'status', session=session))
        require(status['status'] == 'unlocked' and status['serverUrl'] == CLIENT_ORIGIN,
                'FRESH_AUTHENTICATED_UNLOCK_REQUIRED')
        self.state.setdefault('client_sessions', []).append({'profile_id': profile.split('-')[1],
            'session_sha256': digest(session.encode()), 'unlocked': True})
        self.save()
        return profile, session

    def create_item(self, profile, session, value):
        encoded = base64.b64encode(json.dumps(value).encode())
        return json.loads(self.cli(profile, 'create', 'item', payload=encoded, session=session))

    def register_and_seed(self):
        if self.state.get('seeded'):
            return
        require(self.state.get('enrolled'), 'ACTIVATION_AND_ENROLLMENT_REQUIRED')
        self.idle()
        self.inspect()
        self.tls()
        credentials = json.loads(private_read(self.root / 'credentials.json'))
        if not self.state.get('registered'):
            require(not self.state.get('registration_attempted'), 'REGISTRATION_ATTEMPT_REQUIRES_DIAGNOSIS')
            self.state['registration_attempted'] = True
            registration_result = self.root / ('registration-result-' + uuid4().hex + '.json')
            self.state.setdefault('registration_attempts', []).append(registration_result.name)
            self.save()
            run(['node', '-e', browser_registration_program()], payload=json.dumps({**credentials,
                'origin': CLIENT_ORIGIN, 'spki': self.state['tls_spki'], 'result': str(registration_result)}).encode(),
                timeout=300)
            self.state['registered'] = True
            self.save()
        profile, session = self.login('seed')
        try:
            require(not self.state.get('seed_attempted'), 'SEED_RECONCILE_REQUIRED')
            self.state['seed_attempted'] = True
            self.save()
            template = json.loads(self.cli(profile, 'get', 'template', 'item', session=session))
            template.update(name=credentials['item_name'], type=1, login={'username': credentials['username'],
                'password': credentials['login_password'], 'totp': None, 'uris': []})
            item = self.create_item(profile, session, template)
            self.state['item_id'] = item['id']
            self.save()
            self.cli(profile, 'create', 'attachment', '--file', str(self.root / 'attachment.bin'),
                     '--itemid', item['id'], session=session)
            actual = json.loads(self.cli(profile, 'get', 'item', item['id'], session=session))
            require(actual['login']['password'] == credentials['login_password'] and len(actual['attachments']) == 1,
                    'REAL_CLIENT_SEED_DECRYPT_FAILED')
            self.state['attachment_id'] = actual['attachments'][0]['id']
            self.state['attachment_sha256'] = digest(private_read(self.root / 'attachment.bin'))
            self.state['seeded'] = True
            self.save()
        finally:
            self.cli(profile, 'logout')

    def prove(self):
        self.register_and_seed()
        self.inspect()
        if not self.state.get('snapshot_id'):
            job = self.job('backup', f'/instances/{self.instance}/backups', {'label': 'Authenticated synthetic capture'})
            require(job['source_service_outcome'] == 'running' and job['required_copy_outcome'] == 'complete',
                    'COMPLETE_BACKUP_REQUIRED')
            point = self.request('GET', '/snapshots/' + job['result']['snapshot_id'])
            copies = [c for c in point['copies'] if c['backend'] == 'local' and c['destination_id'] == DESTINATION
                      and c['state'] == 'complete']
            require(point['completeness'] == 'complete' and len(copies) == 1, 'EXACT_COMPLETE_LOCAL_COPY_REQUIRED')
            from vaultrewind.server.models import Repository, Snapshot, SnapshotCopy
            with self.sessions() as db:
                captured = db.get(Snapshot, point['id'])
                copy = db.get(SnapshotCopy, copies[0]['id'])
                repository = db.get(Repository, copy.repository_id)
                require(captured.instance_id == self.instance and copy.snapshot_id == captured.id and
                        copy.state == 'complete' and copy.manifest_hash == captured.manifest_hash and
                        repository.instance_id == self.instance and repository.destination_id == DESTINATION,
                        'EXACT_LOCAL_CATALOG_IDENTITY_REQUIRED')
                manifest_sha256 = captured.manifest_hash
            self.state.update(snapshot_id=point['id'], copy_id=copies[0]['id'], manifest_sha256=manifest_sha256)
            self.save()
        credentials = json.loads(private_read(self.root / 'credentials.json'))
        if not self.state.get('mutated'):
            profile, session = self.login('change')
            try:
                require(not self.state.get('mutation_attempted'), 'CLIENT_MUTATION_RECONCILE_REQUIRED')
                self.state['mutation_attempted'] = True
                self.save()
                item = json.loads(self.cli(profile, 'get', 'item', self.state['item_id'], session=session))
                item['login']['password'] = credentials['changed_password']
                self.cli(profile, 'edit', 'item', item['id'], payload=base64.b64encode(json.dumps(item).encode()), session=session)
                self.cli(profile, 'delete', 'attachment', self.state['attachment_id'], '--itemid', item['id'], session=session)
                template = json.loads(self.cli(profile, 'get', 'template', 'item', session=session))
                template.update(name=credentials['marker_name'], type=1)
                marker = self.create_item(profile, session, template)
                self.state['marker_id'] = marker['id']
                self.cli(profile, 'sync', session=session)
                changed = json.loads(self.cli(profile, 'get', 'item', item['id'], session=session))
                require(changed['login']['password'] == credentials['changed_password'] and not changed.get('attachments'),
                        'REAL_CLIENT_POST_CAPTURE_MUTATION_FAILED')
                self.state['mutated'] = True
                self.save()
            finally:
                self.cli(profile, 'logout')
        if not self.state.get('restore_plan'):
            require(not self.state.get('restore_plan_attempted'), 'RESTORE_PLAN_RESPONSE_UNRESOLVED')
            self.state['restore_plan_attempted'] = True
            self.save()
            plan = self.request('POST', '/snapshots/' + self.state['snapshot_id'] + '/restore-plans',
                {'target_id': self.instance, 'copy_id': self.state['copy_id'], 'start_on_completion': True}, expected=201)
            require(plan['target_id'] == self.instance and plan['copy_id'] == self.state['copy_id'] and
                    plan['safety_snapshot_required'], 'EXACT_REPLACEMENT_WITH_SAFETY_REQUIRED')
            self.state['restore_plan'] = plan
            self.save()
        plan = self.state['restore_plan']
        job = self.job('restore', '/restore-plans/' + plan['id'] + '/execute',
                       {'confirmation_token': plan['confirmation_token']})
        require(job['target_activation_outcome'] == 'complete' and job['result'].get('restored_bytes_verified') and
                job['result'].get('application_started'), 'NATIVE_RESTORE_INCOMPLETE')
        safety = self.request('GET', '/snapshots/' + job['result']['safety_snapshot_id'])
        require(safety['safety'] and safety['pinned'] and any(c['backend'] == 'local' and c['state'] == 'complete'
                for c in safety['copies']), 'PINNED_COMPLETE_LOCAL_SAFETY_REQUIRED')
        self.state['safety_snapshot_id'] = safety['id']
        self.save()
        # Completely new appdata, device ID, access token and vault session after restore.
        profile, session = self.login('restored')
        try:
            item = json.loads(self.cli(profile, 'get', 'item', self.state['item_id'], session=session))
            require(item['name'] == credentials['item_name'] and item['login']['username'] == credentials['username'] and
                    item['login']['password'] == credentials['login_password'] and len(item['attachments']) == 1 and
                    item['attachments'][0]['id'] == self.state['attachment_id'], 'RESTORED_CLIENT_DECRYPT_FAILED')
            items = json.loads(self.cli(profile, 'list', 'items', session=session))
            require(all(i['id'] != self.state['marker_id'] for i in items), 'POST_CAPTURE_MARKER_SURVIVED')
            output = self.root / ('download-' + uuid4().hex)
            self.cli(profile, 'get', 'attachment', self.state['attachment_id'], '--itemid', item['id'],
                     '--output', str(output), session=session)
            require(digest(private_read(output)) == self.state['attachment_sha256'] and
                    private_read(output) == private_read(self.root / 'attachment.bin'), 'ATTACHMENT_BYTES_DIFFER')
            self.state['authenticated_proof'] = True
            self.save()
        finally:
            self.cli(profile, 'logout')
        self.finish(job)

    def finish(self, job):
        self.idle()
        self.helper()
        preserved_policy(self.state['baseline']['policy'], self.discovered()['installed_policy'], self.instance)
        journals = self.journals()
        require(all(journals.get(k) == v for k, v in self.state['baseline']['journals'].items()), 'OLD_JOURNAL_CHANGED')
        after = self.other_witness()
        require(after == self.state['baseline']['others'], 'EXISTING_RESOURCES_CHANGED')
        policy = self.request('GET', f'/instances/{self.instance}/policy')
        require(not policy['enabled'] and len(policy['destinations']) == 1 and
                policy['destinations'][0]['destination_id'] == DESTINATION and
                policy['destinations'][0]['required'], 'DISABLED_REQUIRED_LOCAL_ONLY_POLICY_REQUIRED')
        sessions = self.state['client_sessions']
        require(len({s['session_sha256'] for s in sessions}) == len(sessions) and len(sessions) >= 3,
                'FRESH_DISTINCT_CLIENT_SESSIONS_REQUIRED')
        proof = {'result': 'passed', 'synthetic_only': True, 'run_id': self.state['run_id'], 'instance_id': self.instance,
            'native_api_worker_ssh': True, 'vaultwarden_version': '1.37.4', 'image_id': self.state['image_id'],
            'client': self.state['tools'], 'fresh_authenticated_login_and_unlock': True,
            'fresh_client_session_count': len(sessions), 'item_decrypted_and_equal': True,
            'attachment_decrypted_and_byte_equal': True, 'attachment_sha256': self.state['attachment_sha256'],
            'post_capture_item_change_absent': True, 'post_capture_attachment_deletion_absent': True,
            'post_capture_marker_absent': True, 'snapshot_id': self.state['snapshot_id'], 'copy_id': self.state['copy_id'],
            'manifest_sha256': self.state['manifest_sha256'], 'safety_snapshot_id': self.state['safety_snapshot_id'],
            'pinned_complete_local_safety': True, 'restore_plan_id': self.state['restore_plan']['id'],
            'job_ids': {k: v['job_id'] for k, v in self.state['steps'].items()},
            'helper_bundle_sha256': HELPER, 'prior_profile_ids': sorted(self.state['baseline']['policy']['instances']),
            'prior_profiles_preserved': True, 'prior_journals_preserved': True,
            'prior_journal_map_sha256': digest(self.state['baseline']['journals']), 'existing_resources_preserved': after,
            'fixture_policy_disabled_local_only': True, 'fixture_dedicated_bridge': True,
            'fixture_smtp_unconfigured_push_and_icon_download_disabled': True,
            'loopback_port_only': True, 'screenshots_trace_video_disabled': True,
            'private_tls_proxy_forwarded_unchanged_responses': True,
            'tls_certificate_sha256': self.state['tls_certificate_sha256'],
            'plaintext_vault_export_created': False, 'fixture_retained_for_private_review': True,
            'scope': 'Dedicated synthetic account and one login/attachment; no production or real-user authentication claim.'}
        proof.update(self.settled_native_evidence(job))
        history = safe_failures(self.state)
        for previous in self.state.get('prior_failed_runs', []):
            identifier(previous)
            prior = json.loads(private_read(RUNTIME / previous / 'checkpoint.json'))
            require(prior['run_id'] == previous and prior['instance_id'] != self.instance and
                    not prior.get('activated') and not prior.get('registered'), 'PRIOR_ATTEMPT_SCOPE_MISMATCH')
            history.extend(safe_failures(prior))
        proof['harness_failure_chronology'] = sorted(history, key=lambda entry: entry['unix_time'])
        proof['prior_profiles_sha256'] = {k: digest(v) for k, v in self.state['baseline']['policy']['instances'].items()}
        proof['prior_journal_count'] = len(self.state['baseline']['journals'])
        require(job['state'] == 'succeeded', 'RESTORE_SUCCEEDED_REQUIRED')
        # The public report is an allowlist constructed here, never checkpoint serialization.
        serialized = json.dumps(proof, indent=2) + '\n'
        creds = json.loads(private_read(self.root / 'credentials.json'))
        require(all(v not in serialized for v in creds.values()), 'PUBLIC_EVIDENCE_SECRET_BOUNDARY')
        (PROJECT / 'docs/evidence/authenticated-recovery.json').write_text(serialized)
        self.state['complete'] = True
        self.save()

    def settled_native_evidence(self, job):
        """Read-only terminal journal/generation and exact encrypted safety copy."""
        from sqlalchemy import select

        from vaultrewind.server.models import Repository, Snapshot, SnapshotCopy, StorageDestination

        require(job['state'] == 'succeeded' and job['instance_id'] == self.instance and
                all(job['result'].get(key) is True for key in
                    ('candidate_validated', 'public_ports_verified', 'public_endpoint_verified')),
                'NATIVE_PUBLIC_TERMINAL_PROOF_REQUIRED')
        journal = json.loads(private_read(Path('/var/lib/vaultrewind-helper/journals') / (job['id'] + '.json')))
        require(journal['phase'] == 'complete' and journal['instance_id'] == self.instance and
                journal['operation_id'] == job['id'] and journal['active_generation'] == job['id'] and
                journal['watchdog_armed'] is False, 'EXACT_COMPLETED_HELPER_JOURNAL_REQUIRED')
        ack = journal['safety_ack']
        require(ack['snapshot_uuid'] == self.state['safety_snapshot_id'] and
                all(ack.get(key) is True for key in ('durable', 'encrypted', 'pinned', 'stored_copy_verified')),
                'DURABLE_PINNED_ENCRYPTED_SAFETY_ACK_REQUIRED')
        require(len(journal['generation_steps']) == 1, 'EXACT_OWNED_GENERATION_REQUIRED')
        step = journal['generation_steps'][0]
        old = Path(step['old'])
        expected_old = self.root / ('.vrw-' + job['id'] + '-0') / 'old'
        require(old == expected_old and step['mount']['source'] == str(self.root / 'data') and
                step['had_original'] is True, 'OLD_GENERATION_SCOPE_MISMATCH')
        no_symlinks(old)
        require([old.stat().st_dev, old.stat().st_ino] == step['original_identity'],
                'ORIGINAL_GENERATION_NOT_PRESERVED')
        original = json.loads(run(['docker', 'inspect', journal['original']['container_id']]))[0]
        require(original['Config']['Labels'].get('vaultrewind.authenticated-recovery') == self.state['run_id'] and
                not original['State']['Running'] and original['Name'] == '/vrw-old-' + job['id'],
                'OWN_STOPPED_ROLLBACK_CONTAINER_REQUIRED')
        active = self.inspect()
        require(active['Id'] == journal['final_id'] and active['State']['Running'], 'EXACT_ACTIVE_GENERATION_REQUIRED')
        with self.sessions() as db:
            safety = db.get(Snapshot, self.state['safety_snapshot_id'])
            copy = db.scalar(select(SnapshotCopy).where(SnapshotCopy.snapshot_id == safety.id,
                                                       SnapshotCopy.repository_id == ack['repository_id']))
            repository = db.get(Repository, ack['repository_id'])
            destination = db.get(StorageDestination, repository.destination_id)
            require(safety.instance_id == self.instance and safety.safety_for_job_id == job['id'] and
                    copy.state == 'complete' and copy.restic_snapshot_id == ack['restic_snapshot_id'] and
                    repository.instance_id == self.instance and destination.backend == 'local',
                    'EXACT_COMPLETE_NATIVE_LOCAL_SAFETY_REQUIRED')
            point_copy = db.get(SnapshotCopy, self.state['copy_id'])
            return {'native_restore_public_ready': True, 'native_candidate_validated': True,
                'previous_target_generation_preserved': True, 'previous_target_container_preserved_stopped': True,
                'safety_ack_durable_encrypted_pinned_verified': True, 'safety_copy_id': copy.id,
                'safety_repository_id': repository.id, 'safety_restic_snapshot_id': copy.restic_snapshot_id,
                'selected_restic_snapshot_id': point_copy.restic_snapshot_id, 'item_id': self.state['item_id'],
                'attachment_id': self.state['attachment_id'], 'post_capture_marker_id': self.state['marker_id'],
                'helper_restore_journal_sha256': digest(private_read(Path('/var/lib/vaultrewind-helper/journals') /
                                                                     (job['id'] + '.json')))}


def serve_tls(run_id):
    """No request/response/error logging; fixed upstream, private certificate."""
    import http.client
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    identifier(run_id)
    owner = object.__new__(Drill)
    owner.root = RUNTIME / run_id
    owner.state = json.loads(private_read(owner.root / 'checkpoint.json'))
    require(owner.state['run_id'] == run_id, 'TLS_CHECKPOINT_MISMATCH')
    owner.paths = scope(run_id, owner.state['instance_id'])
    owner.inspect()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def forward(self):
            require(self.path.startswith('/') and not self.path.startswith('//'), 'TLS_PROXY_PATH_REJECTED')
            length = int(self.headers.get('Content-Length', '0'))
            require(0 <= length <= 4 * 1024**2, 'TLS_PROXY_REQUEST_LIMIT')
            body = self.rfile.read(length) if length else None
            conn = http.client.HTTPConnection('127.0.0.1', 18280, timeout=60)
            try:
                headers = {k: v for k, v in self.headers.items() if k.lower() not in {'connection', 'transfer-encoding'}}
                conn.request(self.command, self.path, body=body, headers=headers)
                response = conn.getresponse()
                content = response.read(64 * 1024**2)
                self.send_response(response.status)
                for key, value in response.getheaders():
                    if key.lower() not in {'connection', 'transfer-encoding', 'content-length'}:
                        self.send_header(key, value)
                self.send_header('Content-Length', str(len(content)))
                self.end_headers()
                self.wfile.write(content)
            finally:
                conn.close()

        do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = do_HEAD = forward

    class Server(ThreadingHTTPServer):
        def handle_error(self, *args):
            pass

    server = Server(('127.0.0.1', 18443), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(owner.root / 'fixture-cert.pem', owner.root / 'fixture-key.pem')
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--run-id')
    parser.add_argument('--stage', choices=('plan', 'activate', 'prove'), default='plan')
    parser.add_argument('--reviewed-plan-id')
    parser.add_argument('--serve-tls', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.serve_tls:
        require(args.run_id and not args.execute, 'PRIVATE_TLS_SCOPE_REQUIRED')
        serve_tls(args.run_id)
        return 0
    if not args.execute:
        print(json.dumps({'mode': 'prepare', 'mutations': False, 'external_io': False,
            'client_version': CLI_VERSION, 'client_archive_sha256': CLI_ARCHIVE_SHA256,
            'new_fixture_only': True, 'stages': ['plan', 'activate', 'prove']}))
        return 0
    require(args.run_id, 'EXPLICIT_NEW_RUN_UUID_REQUIRED')
    drill = Drill(args.run_id)
    try:
        drill.connect()
        if args.stage == 'plan':
            drill.plan()
        elif args.stage == 'activate':
            drill.activate(args.reviewed_plan_id)
        else:
            require(drill.state.get('activated'), 'ACTIVATION_REQUIRED')
            drill.prove()
        print(json.dumps({'result': 'passed', 'stage': args.stage, 'run_id': args.run_id,
            'instance_id': drill.instance, 'plan_id': drill.state.get('activation_plan', {}).get('plan_id'),
            'complete': drill.state.get('complete', False)}))
        return 0
    except Exception as error:  # noqa: BLE001 - the secret boundary must suppress third-party text
        code = str(error) if isinstance(error, DrillError) and re.fullmatch(r'[A-Z_0-9]+', str(error)) else 'PRIVATE_FAILURE'
        drill.state['failures'].append({'code': code, 'stage': args.stage, 'time': int(time.time())})
        drill.save()
        raise DrillError(code) from None


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except DrillError as error:
        print(json.dumps({'result': 'blocked', 'code': str(error)}))
        raise SystemExit(1) from None

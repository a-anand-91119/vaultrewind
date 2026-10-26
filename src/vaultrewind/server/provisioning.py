"""Explicit administrative SSH activation, separate from constrained operational access.

Only a fixed Python program is executed. Private policy/artifacts use bounded JSON
stdin, and no client value becomes a shell fragment or command argument.
"""
import asyncio
import base64
import hashlib
import json
import shlex
from pathlib import Path

import asyncssh
from sqlalchemy import select

from vaultrewind.core.errors import VaultRewindError

from .db import uid
from .models import Host

# This program is product code, never generated from administrator input.
BOOTSTRAP = r'''
import base64, contextlib, hashlib, json, os, pathlib, re, subprocess, sys, tempfile
LIMIT = 32*1024*1024
try:
    raw = sys.stdin.buffer.read(LIMIT + 1)
    if len(raw) > LIMIT: raise ValueError()
    value = json.loads(raw)
    mode = value['mode']
    if os.geteuid() != 0: raise ValueError()
    def candidate_service():
        expected=value['bundle_sha256']
        if not re.fullmatch('[0-9a-f]{64}',expected): raise ValueError()
        content=base64.b64decode(value['files']['helper.pyz'],validate=True)
        if len(content)>16*1024*1024 or hashlib.sha256(content).hexdigest()!=expected: raise ValueError()
        temporary=tempfile.TemporaryDirectory(prefix='vaultrewind-history-validator-')
        candidate=pathlib.Path(temporary.name)/'helper.pyz'
        candidate.write_bytes(content)
        os.chmod(candidate,0o600)
        sys.path.insert(0,str(candidate))
        from vaultrewind.remote.helper import Helper
        from vaultrewind.remote.policy import Policy
        return temporary,Helper(Policy.load())
    def historical_evidence(service):
        journals=[]
        for path in sorted((service.root/'journals').glob('*.json')):
            raw=path.read_bytes()
            if len(raw)>16*1024*1024: raise ValueError()
            record=json.loads(raw)
            if record.get('watchdog_armed') or record.get('phase') not in ('complete','cancelled','rolled_back','data_restored_service_stopped','cleaned','captured','failed_safe'):
                if path.stem!=record.get('operation_id') or len(journals)>=100: raise ValueError()
                proof=service.historical_status_evidence_locked(record['operation_id'])
                journals.append({**proof,'instance_id':record['instance_id']})
        return {'bundle_sha256':value['bundle_sha256'],'eligible':all(p.get('eligible') is True for p in journals),'journals':journals}
    if mode == 'discover':
        def docker(args):
            r = subprocess.run(['/usr/bin/docker', *args], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30, check=True)
            if len(r.stdout) > 8*1024*1024: raise ValueError()
            return json.loads(r.stdout)
        info = docker(['info', '--format', '{{json .}}'])
        ids = subprocess.run(['/usr/bin/docker','ps','-aq','--no-trunc'],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=30,check=True).stdout.decode().split()
        if len(ids) > 100 or any(not re.fullmatch('[0-9a-f]{64}', x) for x in ids): raise ValueError()
        containers = docker(['inspect', *ids]) if ids else []
        state_root = pathlib.Path('/var/lib/vaultrewind-helper')
        fences=[]
        pending=[]
        if state_root.is_dir():
            for path in (state_root/'fences').glob('*.json'):
                record=json.loads(path.read_bytes())
                if not re.fullmatch('[0-9a-f]{64}',path.stem) or type(record.get('token')) is not int or record['token']<1: raise ValueError()
                fences.append(record['token'])
            for path in (state_root/'journals').glob('*.json'):
                record=json.loads(path.read_bytes())
                if record.get('watchdog_armed') or record.get('phase') not in ('complete','cancelled','rolled_back','data_restored_service_stopped','cleaned','captured','failed_safe'):
                    pending.append({key:record.get(key) for key in ('operation_id','instance_id','phase','activation_started','fencing_token')})
        installed=None
        policy_path=pathlib.Path('/etc/vaultrewind/helper-policy.json')
        if policy_path.is_file() and not policy_path.is_symlink():
            raw_policy=policy_path.read_bytes()
            if len(raw_policy) > 1024*1024: raise ValueError()
            installed=json.loads(raw_policy)
        print(json.dumps({'ok':True,'result':{'fencing_floor':max(fences,default=0),'pending_operations':pending,'machine_id':pathlib.Path('/etc/machine-id').read_text().strip(),'daemon_id':info['ID'],'os':info.get('OSType'),'containers':containers,'systemd':pathlib.Path('/run/systemd/system').is_dir(),'installed_policy':installed}}))
    elif mode == 'historical-review':
        temporary,service=candidate_service()
        from vaultrewind.remote.journal import Locks
        with temporary,Locks(service.root,[]):
            proof=historical_evidence(service)
        print(json.dumps({'ok':True,'result':proof}))
    elif mode in ('install','status'):
        policy_bytes = json.dumps(value['policy'], sort_keys=True, separators=(',',':')).encode()
        expected = value['bundle_sha256']
        if not re.fullmatch('[0-9a-f]{64}',expected): raise ValueError()
        policy_path = pathlib.Path('/etc/vaultrewind/helper-policy.json')
        bundle_path = pathlib.Path('/opt/vaultrewind-helper')/expected/'helper.pyz'
        wrapper = pathlib.Path('/usr/local/libexec/vaultrewind-helper')
        installed = (policy_path.is_file() and not policy_path.is_symlink() and bundle_path.is_file() and
                     hashlib.sha256(bundle_path.read_bytes()).hexdigest() == expected and
                     policy_path.read_bytes() == policy_bytes and wrapper.is_file() and
                     str(bundle_path) in wrapper.read_text() and all(
                         (pathlib.Path('/etc/systemd/system')/name).is_file() and
                         hashlib.sha256((pathlib.Path('/etc/systemd/system')/name).read_bytes()).hexdigest()==value['hashes'][name]
                         for name in ('vaultrewind-watchdog@.service','vaultrewind-reconcile.service')))
        if mode == 'status':
            print(json.dumps({'ok':True,'result':{'installed':installed,'checksum_verified':installed}}))
        else:
            with contextlib.ExitStack() as guard:
                if value.get('historical_upgrade') is not None:
                    temporary,service=candidate_service()
                    guard.enter_context(temporary)
                    from vaultrewind.remote.journal import Locks
                    guard.enter_context(Locks(service.root,[]))
                    observed=historical_evidence(service)
                    if not observed['eligible'] or observed!=value['historical_upgrade']: raise ValueError()
                if not installed:
                    if not re.fullmatch('[a-z_][a-z0-9_-]{0,31}',value['ssh_user']) or value['ssh_user'] == 'root': raise ValueError()
                    expected_names={'helper.pyz','install.py','checksums.json','vaultrewind-watchdog@.service','vaultrewind-reconcile.service'}
                    if set(value['files']) != expected_names: raise ValueError()
                    with tempfile.TemporaryDirectory(prefix='vaultrewind-activation-') as directory:
                        root=pathlib.Path(directory)
                        for name, encoded in value['files'].items():
                            data=base64.b64decode(encoded,validate=True)
                            if hashlib.sha256(data).hexdigest()!=value['hashes'][name]: raise ValueError()
                            (root/name).write_bytes(data)
                            os.chmod(root/name,0o600)
                        if hashlib.sha256((root/'helper.pyz').read_bytes()).hexdigest()!=expected: raise ValueError()
                        (root/'policy.json').write_bytes(policy_bytes)
                        os.chmod(root/'policy.json',0o600)
                        subprocess.run(['/usr/bin/python3','-I',str(root/'install.py'),'--policy',str(root/'policy.json'),'--ssh-user',value['ssh_user'],'--bundle-sha256',expected],check=True,timeout=180,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            print(json.dumps({'ok':True,'result':{'installed':True,'checksum_verified':True}}))
    else: raise ValueError()
except Exception:
    print(json.dumps({'ok':False,'error':{'code':'HELPER_ACTIVATION_FAILED'}}))
    sys.exit(1)
'''


class Provisioner:
    def __init__(self, adapters):
        self.adapters = adapters
        self.settings, self.sessions, self.store = adapters.settings, adapters.sessions, adapters.secrets

    def bundle(self):
        root = self.settings.helper_bundle_dir
        if root is None:
            candidates = [Path('/app/helper-bundle'), Path(__file__).resolve().parents[3] / '.runtime/helper-bundle']
            root = next((p for p in candidates if (p / 'checksums.json').is_file()), candidates[0])
        names = {'helper.pyz','install.py','checksums.json','vaultrewind-watchdog@.service','vaultrewind-reconcile.service'}
        try:
            raw = {n: (root/n).read_bytes() for n in names}
            checksums = json.loads(raw['checksums.json'])
            actual = {n: hashlib.sha256(b).hexdigest() for n, b in raw.items()}
            if sum(len(b) for b in raw.values()) > 16*1024*1024 or any(checksums.get(n) != actual[n] for n in names - {'checksums.json'}):
                raise ValueError()
        except (OSError, ValueError):
            raise VaultRewindError('HELPER_BUNDLE_UNAVAILABLE', 'Build the reviewed packaged helper bundle before activation.') from None
        return {'files': {n: base64.b64encode(v).decode() for n,v in raw.items()}, 'hashes': actual,
                'bundle_sha256': actual['helper.pyz']}

    def admin_request(self, host_id, payload):
        with self.sessions() as db:
            host = db.get(Host, host_id)
            if not host.activation_credential_id:
                raise VaultRewindError('ACTIVATION_CREDENTIAL_REQUIRED', 'Provide a distinct administrative activation credential, then remove it after activation.')
            credential = self.store.get(db, host.activation_credential_id)
            config = {'endpoint':host.endpoint,'port':host.port,'host_public_key':host.host_public_key,**credential}
        async def run():
            try:
                pinned = asyncssh.import_public_key(config['host_public_key'])
                private = asyncssh.import_private_key(config['private_key'], config.get('passphrase'))
                command = ('/usr/bin/python3 -I -c ' if config['username'] == 'root' else
                           'sudo -n -- /usr/bin/python3 -I -c ') + shlex.quote(BOOTSTRAP)
                raw = json.dumps(payload,separators=(',',':')).encode()
                if len(raw)>32*1024*1024:
                    raise VaultRewindError('PROTOCOL_LIMIT', 'Activation package exceeds the bounded transport limit.')
                async with asyncio.timeout(240), asyncssh.connect(config['endpoint'],port=config['port'],username=config['username'],  # noqa: SIM117
                        client_keys=[private],known_hosts=([pinned],[],[]),agent_path=None,agent_forwarding=False,
                        config=[],connect_timeout=20,login_timeout=20) as connection:
                    async with connection.create_process(command,encoding=None,stderr=asyncssh.DEVNULL) as process:
                        process.stdin.write(raw)
                        process.stdin.write_eof()
                        output = bytearray()
                        while block := await process.stdout.read(65536):
                            output.extend(block)
                            if len(output)>16*1024*1024:
                                raise VaultRewindError('PROTOCOL_LIMIT', 'Administrative discovery response exceeds its bound.')
                        await process.wait_closed()
                        value=json.loads(output)
                        if process.exit_status != 0 or not value.get('ok'):
                            raise VaultRewindError('HELPER_ACTIVATION_FAILED', 'Host setup did not complete; inspect the installation prerequisites.')
                        return value['result']
            except asyncssh.HostKeyNotVerifiable:
                raise VaultRewindError('SSH_HOST_KEY_CHANGED','SSH host key differs from the explicitly verified enrollment key.') from None
            except (asyncssh.Error, OSError, TimeoutError, ValueError):
                raise VaultRewindError('HELPER_ACTIVATION_FAILED','Administrative SSH failed; review prerequisites before retrying.') from None
        return asyncio.run(run())

    def installed_instances(self, discovered):
        installed = (discovered.get('installed_policy') or {}).get('instances') or {}
        return installed if isinstance(installed, dict) else {}

    def enrolled_instances(self, host_id):
        """Controller registrations for this host: remote instance ID -> container ID."""
        from .models import Instance
        with self.sessions() as db:
            rows = db.scalars(select(Instance).where(Instance.host_id == host_id, Instance.archived.is_(False)))
            return {row.id: row.container_id for row in rows}

    def discover_host(self, host_id):
        value = self.admin_request(host_id, {'mode':'discover'})
        if value.get('os')!='linux':
            raise VaultRewindError('UNSUPPORTED_INSTALLATION','Only Linux Docker Vaultwarden is supported.')
        installed = self.installed_instances(value)
        by_container = {item.get('container_id'): rid for rid, item in installed.items() if isinstance(item, dict) and item.get('container_id')}
        for rid, cid in self.enrolled_instances(host_id).items():
            by_container.setdefault(cid, rid)
        proposals=[]
        for container in value['containers']:
            name=container.get('Name','').lstrip('/')
            env=dict(x.split('=',1) for x in container['Config'].get('Env',[]) if '=' in x)
            if not any(m.get('Destination')=='/data' for m in container.get('Mounts',[])):
                continue
            database=env.get('DATABASE_URL','')
            if database and ':' in database and not database.startswith('sqlite:'):
                continue
            # The full helper's readonly discovery/preflight performs the authoritative layout/security validation.
            # An already enrolled container keeps its remote instance identity; adding instances never re-mints IDs.
            ident=by_container.get(container['Id']) or uid()
            mounts=[]
            supported=True
            for index,mount in enumerate(container['Mounts']):
                if mount['Type'] not in ('bind','volume') or (mount['Type']=='volume' and mount.get('Driver','local')!='local'):
                    supported=False
                    break
                item={'type':mount['Type'],'source':mount['Source'],'target':mount['Destination'],
                    'read_only':not mount['RW'],'snapshot_path':'data' if mount['Destination']=='/data' else f'deployment/mounts/m{index}'}
                if mount['Type']=='volume': item['volume_name']=mount['Name']
                mounts.append(item)
            if not supported: continue
            policy={'revision':1,'container_id':container['Id'],'container_name':name,'mounts':mounts,
                'allowed_operations':['discover','preflight','capture','export','stage_restore','commit_restore','rollback','status','cancel','cleanup'],
                'allowed_image_ids':[container['Image']],'allowed_networks':[container['HostConfig'].get('NetworkMode','bridge')],
                'port_bindings':container['HostConfig'].get('PortBindings') or {},'additional_files':{},'dependency_inventory':[],
                'external_dependencies_ready':False,'ownership':'exclusive','capture_budget':300,'restore_budget':900,
                'validation_window':180,'max_archive_bytes':self.settings.per_job_quota_bytes,
                'free_space_reserve':self.settings.min_free_bytes,'recovery_profile':{'revision':1}}
            if isinstance(installed.get(ident), dict):
                # Preserve the administrator-approved instance policy (budgets, dependencies, overlays) already installed.
                policy=installed[ident]
            proposals.append({'remote_instance_id':ident,'container_id':container['Id'],'name':name,'policy':policy,
                              'enrolled': ident in installed or ident in self.enrolled_instances(host_id)})
        return {'machine_id':value['machine_id'],'daemon_id':value['daemon_id'],'systemd':value['systemd'],
                'proposals':proposals,'fencing_floor':value.get('fencing_floor',0),'pending_operations':value.get('pending_operations',[]),
                'installed_instances':sorted(installed),'database_engine':'sqlite','recovery_verified':False}

    def activation_plan(self, host_id, policy):
        from vaultrewind.remote.policy import Policy
        if not isinstance(policy, dict) or not isinstance(policy.get('instances'), dict):
            raise VaultRewindError('POLICY_INVALID', 'The host policy must enroll instances.')
        discovered=self.admin_request(host_id, {'mode':'discover'})
        if discovered.get('machine_id')!=policy.get('machine_id') or discovered.get('daemon_id')!=policy.get('daemon_id') or not discovered.get('systemd'):
            raise VaultRewindError('HOST_CHANGED','Verify the Linux/Docker/systemd identity before activation.')
        bundle=self.bundle()
        historical_upgrade = None
        if discovered.get('pending_operations'):
            historical_upgrade = self.admin_request(host_id, {'mode':'historical-review', **bundle})
            expected_ids = sorted(p['operation_id'] for p in discovered['pending_operations'])
            observed_ids = sorted(p['operation_id'] for p in historical_upgrade.get('journals', []))
            if (historical_upgrade.get('eligible') is not True or observed_ids != expected_ids
                    or historical_upgrade.get('bundle_sha256') != bundle['bundle_sha256']):
                raise VaultRewindError('RECONCILIATION_REQUIRED','Reconcile the prior host operation before installation or policy replacement.')
        # Installation replaces the whole root policy file, so instances enrolled earlier must be carried over:
        # the installed policy is the base, the request overrides/adds, and nothing the controller still
        # manages may disappear.
        installed = self.installed_instances(discovered)
        merged = {**installed, **policy['instances']}
        policy = {**policy, 'instances': merged}
        dropped = sorted(rid for rid in self.enrolled_instances(host_id) if rid not in merged)
        if dropped:
            raise VaultRewindError('POLICY_DROPS_ENROLLED_INSTANCE', 'The proposed host policy omits an enrolled instance; remove the instance from the dashboard first.', count=len(dropped))
        Policy(policy)  # exact root policy schema, canonical paths, supported drivers, no shell hooks
        preserved = sorted(rid for rid in installed if rid not in policy['instances'] or policy['instances'][rid] == installed[rid])
        changes=['Install checksum-pinned helper executable and root-owned enrolled policy.',
                 'Install narrow sudo entrypoint for the operational SSH account.',
                 'Install and enable watchdog and boot recovery systemd units.']
        if preserved:
            changes.append(f'Keep {len(preserved)} previously enrolled instance(s) in the root policy.')
        if historical_upgrade:
            changes.append(f'Reconcile {len(historical_upgrade["journals"])} proven superseded historical status record(s); preserve their original history, warnings and generations.')
        return {'fencing_floor':discovered.get('fencing_floor',0),'host_id':host_id,'policy':policy,'bundle_sha256':bundle['bundle_sha256'],'hashes':bundle['hashes'],
                'historical_upgrade': historical_upgrade,
                'checksum_verified':True,'protocol_version':1,'preserved_instances':preserved,
                'safe_changes':changes,
                'safe_prerequisites':['Linux, Python 3, Docker and running systemd are required.',
                    'No application stop or capture occurs during activation.']}

    def activate(self, host_id, plan, operation_id, token, reconcile=False):
        bundle=self.bundle()
        if bundle['bundle_sha256']!=plan['bundle_sha256'] or bundle['hashes']!=plan['hashes']:
            raise VaultRewindError('TARGET_CHANGED','The packaged helper changed after plan review.')
        with self.sessions() as db:
            user=db.get(Host,host_id).username
        if user=='root':
            raise VaultRewindError('ACTIVATION_USER_UNSAFE','Use a dedicated non-root operational SSH account.')
        result=self.admin_request(host_id,{'mode':'status' if reconcile else 'install','policy':plan['policy'],'ssh_user':user,
            'historical_upgrade':plan.get('historical_upgrade'),**bundle})
        if not result.get('installed'):
            raise VaultRewindError('HELPER_ACTIVATION_FAILED','Partial activation requires a newly reviewed installation plan.')
        for historical in (plan.get('historical_upgrade') or {}).get('journals', []):
            remote, _ = self.adapters.remote(host_id)
            status = asyncio.run(remote.request('status', historical['instance_id'], historical['operation_id'], token))
            if (status.get('phase') != 'complete' or status.get('historical_status_reconciled') is not True
                    or status.get('historical_superseded_by') != historical['superseded_by']):
                raise VaultRewindError('RECONCILIATION_REQUIRED', 'Historical status evidence changed; preserve every generation and review the host.')
        readiness = {}
        for remote_id in plan['policy']['instances']:
            remote,_=self.adapters.remote(host_id)
            preflight=asyncio.run(remote.request('preflight',remote_id,operation_id,token,{'controller_time':__import__('datetime').datetime.now(__import__('datetime').UTC).isoformat()}))
            if not preflight.get('recovery_verified') or preflight.get('protocol_version')!=1:
                raise VaultRewindError('HELPER_NOT_READY','Installed helper recovery verification failed.')
            readiness[remote_id] = {k: preflight.get(k) for k in ('restore_ready', 'restore_error_code',
                'current_public_ports_ready', 'current_public_error_code', 'empty_target', 'fingerprint', 'resource_keys')}
        return {'checksum_verified':True,'protocol_version':1,'recovery_verified':True,'instance_readiness':readiness}

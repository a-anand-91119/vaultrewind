#!/usr/bin/env python3
"""Explicitly prepare synthetic localhost Docker/SSH/systemd fixtures only."""
import hashlib
import json
import subprocess
from pathlib import Path
from uuid import uuid4

from scripts.prove_application import IMAGE, healthy, run, seed

root=Path('/srv/vaultrewind-fixtures');root.mkdir(mode=0o755,exist_ok=True)
private=Path('.runtime/ssh');private.mkdir(parents=True,exist_ok=True,mode=0o700)
source=root/'source'/'data';source.mkdir(parents=True,exist_ok=True,mode=0o700)
(root/'alternate').mkdir(exist_ok=True,mode=0o755)
if subprocess.run(['id','vrfixture'],capture_output=True, check=False).returncode != 0:
 run('useradd','--create-home','--shell','/bin/sh','vrfixture')
if not (private/'id_ed25519').exists():run('ssh-keygen','-q','-t','ed25519','-N','','-f',str(private/'id_ed25519'))
home=Path('/home/vrfixture/.ssh');home.mkdir(exist_ok=True,mode=0o700)
(home/'authorized_keys').write_text('restrict,command="sudo -n -- /usr/local/libexec/vaultrewind-helper" '+(private/'id_ed25519.pub').read_text())
(home/'authorized_keys').chmod(0o600)
run('chown','-R','vrfixture:vrfixture',str(home))
subprocess.run(['docker','network','create','--internal','vaultrewind-fixture-net'],capture_output=True, check=False)
inspect=subprocess.run(['docker','inspect','vr-ssh-source'],capture_output=True, check=False)
if inspect.returncode:
 run('docker','run','-d','--name','vr-ssh-source','--label','vaultrewind.fixture=true','--network','vaultrewind-fixture-net','-p','127.0.0.1:18180:80','--mount',f'type=bind,source={source},target=/data',IMAGE)
 healthy('vr-ssh-source');run('docker','stop','--time','30','vr-ssh-source');seed(source);run('docker','start','vr-ssh-source');healthy('vr-ssh-source')
container=json.loads(run('docker','inspect','vr-ssh-source'))[0]
source_id,alternate_id=str(uuid4()),str(uuid4())
base={'revision':1,'container_id':container['Id'],'container_name':'vr-ssh-source','allowed_operations':['discover','preflight','capture','export','stage_restore','commit_restore','rollback','status','cancel','cleanup'],'allowed_image_ids':[container['Image']],'allowed_networks':['vaultrewind-fixture-net'],'port_bindings':{'80/tcp':[{'HostIp':'127.0.0.1','HostPort':'18180'}]},'mounts':[{'type':'bind','source':str(source),'target':'/data','read_only':False,'snapshot_path':'data'}],'additional_files':{},'dependency_inventory':[],'external_dependencies_ready':True,'ownership':'exclusive','capture_budget':30,'restore_budget':180,'validation_window':120,'max_archive_bytes':2*1024**3,'max_members':10000,'free_space_reserve':16*1024**2,'recovery_profile':{'revision':1}}
alternate={**base,'container_id':None,'container_name':'vr-ssh-alternate','port_bindings':{'80/tcp':[{'HostIp':'127.0.0.1','HostPort':'18181'}]},'mounts':[{'type':'bind','source':str(root/'alternate'/'data'),'target':'/data','read_only':False,'snapshot_path':'data'}],'recovery_profile':{'revision':1,'environment':{'DOMAIN':'http://synthetic-alternate.invalid'},'network':'vaultrewind-fixture-net','port_bindings':{'80/tcp':[{'HostIp':'127.0.0.1','HostPort':'18181'}]}}}
policy={'schema_version':1,'machine_id':Path('/etc/machine-id').read_text().strip(),'daemon_id':json.loads(run('docker','info','--format','{{json .}}'))['ID'],'instances':{source_id:base,alternate_id:alternate}}
(private/'policy.json').write_text(json.dumps(policy,indent=2));(private/'policy.json').chmod(0o600)
run('python3','helper/build_bundle.py','.runtime/helper-bundle')
bundle=Path('.runtime/helper-bundle');digest=hashlib.sha256((bundle/'helper.pyz').read_bytes()).hexdigest()
run('python3',str(bundle/'install.py'),'--policy',str(private/'policy.json'),'--ssh-user','vrfixture','--bundle-sha256',digest)
config={'endpoint':'127.0.0.1','port':22,'username':'vrfixture','host_public_key':Path('/etc/ssh/ssh_host_ed25519_key.pub').read_text(),'private_key':(private/'id_ed25519').read_text()}
(private/'config.json').write_text(json.dumps(config));(private/'config.json').chmod(0o600)
(private/'identities.json').write_text(json.dumps({'source_id':source_id,'alternate_id':alternate_id}));(private/'identities.json').chmod(0o600)
print('Synthetic localhost SSH/Docker/systemd fixture activated; private material is restricted to .runtime/ssh.')

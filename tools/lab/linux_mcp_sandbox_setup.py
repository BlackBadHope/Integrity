# SPDX-License-Identifier: BUSL-1.1
"""Provision only the Ubuntu LAB's transient MCP sandbox and a forced SSH key.

Input is the fresh guest-generated public key. No production credentials.
The controller's existing management key and sshd configuration are preserved.
"""
from pathlib import Path
import grp
import hashlib
import json
import os
import pwd
import re
import shutil
import socket
import subprocess
import sys

LAUNCHER = Path('/usr/local/sbin/integrity-lab-mcp-stdio')
# Filled from lab.json by the Windows-side provisioner (windows_native_binding.provision)
# before this source is sent to the guest; the guest has no copy of the configuration.
SETTINGS = r'''@SETTINGS@'''
ENTRY = r'''#!/usr/bin/python3
"""Root-owned constant launcher; MCP always runs as lab with no new privileges."""
import json,os,pwd,subprocess,sys,uuid
from pathlib import Path
HOME=__HOME__
if os.geteuid()!=0 or os.uname().nodename!=__LINUX_HOSTNAME__:
    raise SystemExit('LAB root launcher required')
if len(sys.argv)>2 or (len(sys.argv)==2 and sys.argv[1]!='--probe'):
    raise SystemExit('No arbitrary command arguments')
probe=len(sys.argv)==2
args=['/usr/bin/systemd-run','--quiet','--pipe','--wait','--collect',
 '--service-type=exec','--unit=integrity-lab-mcp-'+uuid.uuid4().hex,
 '--uid=lab','--gid=lab','--working-directory='+HOME+'/backend',
 '--property=UMask=0077','--property=NoNewPrivileges=yes',
 '--property=CapabilityBoundingSet=','--property=AmbientCapabilities=',
 '--property=PrivateNetwork=yes','--property=PrivateDevices=yes',
 '--property=PrivateTmp=yes','--property=ProtectSystem=strict',
 '--property=ProtectHome=tmpfs','--property=BindPaths='+HOME+'/backend',
 '--property=ReadWritePaths='+HOME+'/backend',
 '--property=InaccessiblePaths=-/run/dbus -/run/user -/run/systemd/private -/root -/mnt -/media',
 '--property=ProtectKernelTunables=yes','--property=ProtectKernelModules=yes',
 '--property=ProtectKernelLogs=yes','--property=ProtectControlGroups=yes',
 '--property=ProtectClock=yes','--property=ProtectHostname=yes',
 '--property=ProtectProc=invisible','--property=ProcSubset=pid',
 '--property=RestrictSUIDSGID=yes','--property=RestrictRealtime=yes',
 '--property=RestrictNamespaces=yes','--property=LockPersonality=yes',
 '--property=RestrictAddressFamilies=AF_UNIX',
 '--property=SystemCallArchitectures=native',
 '--property=SystemCallFilter=~@privileged @debug @mount @reboot @swap',
 '--property=TasksMax=32','--property=MemoryMax=512M',
 '--property=RuntimeMaxSec=900','--property=TimeoutStopSec=5',
 '--setenv=HOME='+HOME,'--setenv=PYTHONNOUSERSITE=1',
 '--setenv=PYTHONDONTWRITEBYTECODE=1',
 '/opt/integrity-lab/venv/bin/python','-I','-B']
if probe:
 args+=['-c',r"""
import errno,json,os,pathlib,socket,subprocess,sys
home=pathlib.Path(os.environ['HOME']);root=home/'backend'; checks=[]
def check(name,fn):
 try:fn();checks.append({'claim':name,'status':'PASS'})
 except Exception as e:checks.append({'claim':name,'status':'FAIL','reason':type(e).__name__+': '+str(e)[:160]})
def own():
 p=root/'sandbox-positive.txt';p.write_text('Synthetic MCP sandbox probe.\n');assert p.read_text().startswith('Synthetic');p.unlink()
def outside():
 p=home/'mcp-outside-sentinel.txt'
 try:p.open('rb').close()
 except (PermissionError,FileNotFoundError):return
 raise AssertionError('Outside sentinel openable')
def readonly():
 try:p=pathlib.Path('/opt/integrity-lab/mcp-write-probe');p.write_text('Synthetic')
 except (PermissionError,OSError) as e:
  assert e.errno in {errno.EROFS,errno.EACCES,errno.EPERM};return
 raise AssertionError('Runtime writable')
def network():
 try:s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.close()
 except OSError as e:
  assert e.errno in {errno.EAFNOSUPPORT,errno.EPERM,errno.EACCES};return
 raise AssertionError('AF_INET socket allowed')
def privilege():
 r=subprocess.run(['/usr/bin/sudo','-n','/usr/bin/id','-u'],capture_output=True,text=True,timeout=3)
 assert r.returncode!=0 and r.stdout.strip()!='0'
def identity():
 assert os.geteuid()==1000
 status=pathlib.Path('/proc/self/status').read_text()
 assert 'NoNewPrivs:\t1' in status and 'CapEff:\t0000000000000000' in status
check('unprivileged_no_new_privileges_no_capabilities',identity)
check('own_backend_read_write',own)
check('outside_home_sentinel_hidden',outside)
check('runtime_read_only',readonly)
check('network_socket_policy_denied',network)
check('sudo_escalation_denied',privilege)
sys.path.insert(0,'/opt/integrity-lab/tools')
def core():
 import linux_backend
 s=linux_backend.build()
 assert s.native_trust.verify_genesis()['genesis_id']==__GENESIS_ID__
 assert s.turn_memory.namespace.startswith('sha256:')
check('real_POSIX_core_build_and_genesis',core)
report={'schema':'integrity-lab.linux-mcp-os-sandbox.v1','checks':checks,'status':'PASS' if all(x['status']=='PASS' for x in checks) else 'FAIL','models':'NOT_RUN','agents':'NOT_RUN','benchmarks':'NOT_RUN'}
print(json.dumps(report));sys.exit(0 if report['status']=='PASS' else 1)
"""]
else:
 args+=['/opt/integrity-lab/tools/linux_backend.py','--stdio']
os.execv(args[0],args)
'''


def settings():
    if SETTINGS.startswith('@'):
        raise RuntimeError('Unfilled lab settings; send this source through windows_native_binding.provision')
    return json.loads(SETTINGS)


def main():
    config=settings()
    if sys.platform!='linux' or os.geteuid()!=0 or socket.gethostname()!=config['linux_hostname']:
        raise RuntimeError('Only the root of the new Linux LAB may provision this launcher')
    account=pwd.getpwnam('lab')
    assert account.pw_uid==1000 and account.pw_dir==config['linux_home']
    assert Path('/usr/bin/systemd-run').is_file() and Path('/opt/integrity-lab/tools/linux_backend.py').is_file()
    key=sys.argv[1] if len(sys.argv)==2 else ''
    if not re.fullmatch(r'ssh-ed25519 [A-Za-z0-9+/=]{60,120}',key):
        raise ValueError('Fresh LAB public key expected')
    # Idempotence is exact; an unexpected launcher is never overwritten.
    entry=ENTRY.replace('__HOME__',repr(config['linux_home'])).replace('__LINUX_HOSTNAME__',repr(config['linux_hostname']))
    entry=entry.replace('__GENESIS_ID__',repr(config['genesis_id']))
    encoded=entry.encode()
    if LAUNCHER.exists() and LAUNCHER.read_bytes()!=encoded:
        old_launcher=LAUNCHER.read_bytes()
        # No configured preimage pin (null) means an unexpected launcher is never replaced.
        if hashlib.sha256(old_launcher).hexdigest()!=config['launcher_migration_preimage_sha256']:
            raise RuntimeError('Launcher preimage differs; review required')
        rollback=LAUNCHER.with_name(LAUNCHER.name+'.before-namespace-fix')
        if not rollback.exists():rollback.write_bytes(old_launcher);rollback.chmod(0o600)
        LAUNCHER.write_bytes(encoded)
    if not LAUNCHER.exists():
        LAUNCHER.write_bytes(encoded)
        LAUNCHER.chmod(0o755)
    assert LAUNCHER.stat().st_uid==0 and not LAUNCHER.stat().st_mode & 0o022
    home=Path(account.pw_dir)
    sentinel=home/'mcp-outside-sentinel.txt'
    if not sentinel.exists():
        sentinel.write_text('Synthetic outside the MCP allowed backend.\n')
    if sentinel.read_text()!='Synthetic outside the MCP allowed backend.\n':
        raise RuntimeError('Unexpected sentinel preimage')
    os.chown(sentinel,account.pw_uid,account.pw_gid);sentinel.chmod(0o600)
    ssh=home/'.ssh';assert ssh.is_dir() and not ssh.is_symlink()
    auth=ssh/'authorized_keys'
    old=auth.read_bytes()
    line='restrict,from="'+config['windows_guest_ip']+'",command="sudo -n '+str(LAUNCHER)+'" '+key+' IntegrityLAB-native-stdio\n'
    if line.encode() not in old.splitlines(keepends=True):
        if b'IntegrityLAB-native-stdio' in old:
            raise RuntimeError('An existing native key needs operator reconciliation')
        backup=auth.with_name('authorized_keys.before-native-stdio')
        if not backup.exists():
            backup.write_bytes(old);os.chown(backup,account.pw_uid,account.pw_gid);backup.chmod(0o600)
        with auth.open('ab') as stream:stream.write((b'\n' if old and not old.endswith(b'\n') else b'')+line.encode())
    os.chown(auth,account.pw_uid,account.pw_gid);auth.chmod(0o600)
    print(json.dumps({'status':'PROVISIONED_NOT_ACCEPTED','root_owned_launcher':True,'management_key_preserved':True,
        'native_key':'FORCED_COMMAND_ONLY_FROM_WINDOWS_LAB','host_changes':0,'models':'NOT_RUN','agents':'NOT_RUN'}))


if __name__=='__main__':
    main()

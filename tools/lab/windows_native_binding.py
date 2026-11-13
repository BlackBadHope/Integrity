# SPDX-License-Identifier: BUSL-1.1
"""Technical Native provisioning only in the Windows LAB guest; no model/agent API calls."""
from pathlib import Path
import argparse,base64,hashlib,importlib.util,json,os,shlex,subprocess,sys,tomllib
sys.path.insert(0,str(Path(__file__).absolute().parent))
import lab_config

ROOT=Path('C:/IntegrityLAB')
CONTROL=ROOT/'control/preflight-labadmin'
SSH=Path('C:/Windows/System32/OpenSSH/ssh.exe')
KEY=CONTROL/'native-stdio-key'


def ssh_args(native=False):
    return [str(SSH),'-T','-i',str(KEY if native else CONTROL/'linux-management-key'),
        '-o','IdentitiesOnly=yes','-o','StrictHostKeyChecking=yes',
        '-o','UserKnownHostsFile='+str(CONTROL/'linux-known-hosts'),'-o','BatchMode=yes',
        '-o','ConnectTimeout=5','lab@'+lab_config.setting('network.linux_guest_ip')]


def remote(command,source=None,native=False,timeout=90):
    return subprocess.run([*ssh_args(native),command],input=source,
        capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=timeout)


def successful(p):
    if p.returncode:raise RuntimeError('LAB technical command failed: '+p.stderr[-600:])
    return p.stdout


def save(name,value):
    (ROOT/'evidence'/name).write_text(json.dumps(value,indent=2)+'\n')
    print(json.dumps(value))


def provision():
    if not KEY.exists():
        p=subprocess.run([str(SSH.with_name('ssh-keygen.exe')),'-q','-t','ed25519','-N','','-f',str(KEY)],capture_output=True,timeout=15)
        if p.returncode:raise RuntimeError('Fresh LAB native transport key generation failed')
    public=KEY.with_name(KEY.name+'.pub').read_text().split()
    assert public[0]=='ssh-ed25519' and len(public)>=2
    source=(CONTROL/'linux_mcp_sandbox_setup.py').read_text(encoding='utf-8')
    source=lab_config.fill(source,quote=lambda value:value,SETTINGS=json.dumps({
        'linux_hostname':lab_config.setting('vms.linux.hostname'),'linux_home':lab_config.setting('linux_guest.home'),
        'genesis_id':lab_config.setting('linux_guest.genesis_id'),
        'launcher_migration_preimage_sha256':lab_config.setting('linux_guest.launcher_migration_preimage_sha256',allow_null=True),
        'windows_guest_ip':lab_config.setting('network.windows_guest_ip')}))
    result=json.loads(successful(remote('sudo -n /usr/bin/python3 -I -B - '+shlex.quote(' '.join(public[:2])),source)))
    save('native-provision.json',result)


def sandbox():
    baseline=successful(remote('test -r "$HOME"/mcp-outside-sentinel.txt && printf OUTSIDE_BASELINE_PRESENT'))
    assert baseline=='OUTSIDE_BASELINE_PRESENT'
    p=remote('sudo -n /usr/local/sbin/integrity-lab-mcp-stdio --probe')
    try:report=json.loads(p.stdout)
    except ValueError:
        report={'status':'FAIL_STARTUP','stderr':p.stderr[-1200:],'checks':[]}
    report['outside_sentinel_baseline']='READABLE_BEFORE_SANDBOX'
    report['exit_code']=p.returncode
    save('mcp-os-sandbox.json',report)
    if p.returncode or report['status']!='PASS':raise RuntimeError('Real MCP process sandbox failed; see report')


def bindings():
    source=r'''
import json,sys
sys.path.insert(0,'/opt/integrity-lab/tools')
import linux_backend
from integrity_guardian.medor_architecture import CUSTODY_CHECKPOINT_ID
s=linux_backend.build()
print(json.dumps({'seed_namespace':'seed://project/integrity-lab-vm-preflight',
 'namespace_fingerprint':s.turn_memory.namespace,'architecture_checkpoint_id':CUSTODY_CHECKPOINT_ID,
 'genesis_id':s.native_trust.verify_genesis()['genesis_id']}))
'''
    value=json.loads(successful(remote('/opt/integrity-lab/venv/bin/python -I -B -',source)))
    assert value.pop('genesis_id')==lab_config.setting('linux_guest.genesis_id')
    (CONTROL/'native-bindings.json').write_text(json.dumps(value,indent=2)+'\n')
    frames=[{'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2025-11-25','capabilities':{},'clientInfo':{'name':'lab-native-provision','version':'1'}}},
        {'jsonrpc':'2.0','method':'notifications/initialized'}, {'jsonrpc':'2.0','id':2,'method':'tools/list','params':{}}]
    # Even this deliberate shell request must be replaced by the forced MCP entry.
    p=remote("printf NATIVE_SHELL_ESCAPE",''.join(json.dumps(f)+'\n' for f in frames),native=True)
    output=successful(p)
    assert 'NATIVE_SHELL_ESCAPE' not in output
    values=[json.loads(line) for line in output.splitlines() if line.strip()]
    assert 'result' in next(x for x in values if x.get('id')==1)
    tools=next(x for x in values if x.get('id')==2)['result']['tools']
    assert len(tools)==19
    (CONTROL/'native-tools.json').write_text(json.dumps({'tools':tools},indent=2)+'\n')
    p=subprocess.run([*ssh_args(True)[:-1],'-W','127.0.0.1:22',ssh_args(True)[-1]],capture_output=True,text=True,timeout=15)
    assert p.returncode!=0 and 'administratively prohibited' in p.stderr.lower()
    save('native-transport.json',{'status':'PASS','real_namespace_bindings':value,'native_tools':len(tools),
        'forced_command_shell_replacement':'PASS','TCP_forwarding_denied':'PASS','MCP_inside_Linux_OS_sandbox':'PASS',
        'owner_turn_enrollment':'NOT_RUN','models':'NOT_RUN','agents':'NOT_RUN','benchmarks':'NOT_RUN'})


def profiles():
    from integrity_client_memory import native_install,native_runtime
    selected=json.loads((CONTROL/'native-bindings.json').read_text())
    # A generic initialize deliberately gets the server's 19-tool legacy surface.
    # Export the installed server's unmodified current contract, then require the
    # real broker to negotiate and compare it with the live isolated upstream.
    source="from integrity_guardian import memory_synapse_mcp as c;import json;print(json.dumps({'tools':c.tools()}))"
    tools=json.loads(successful(remote('/opt/integrity-lab/venv/bin/python -I -B -',source)))
    (CONTROL/'native-current-tools.json').write_text(json.dumps(tools,indent=2)+'\n')
    upstream={'command':str(SSH),'args':ssh_args(True)[1:]+['MCP_ONLY_FORCED_ENTRY'],'env':{}}
    outputs=[]
    for actor in ['LAB-A','LAB-B']:
        parent=CONTROL/'native-profiles';parent.mkdir(exist_ok=True)
        target=parent/actor
        if not target.exists():native_install.build('codex',upstream,selected,target,tools)
        value,_=native_runtime.verify(target/'profile.json')
        assert native_runtime.main(['--profile',str(target/'profile.json'),'probe'])==0
        workspace=ROOT/'workspaces'/actor
        dest=workspace/'.codex';dest.mkdir(exist_ok=True)
        for name in ['config.toml','hooks.json']:
            source=target/'codex-workspace/.codex'/name
            p=dest/name
            data=source.read_bytes()
            if p.exists() and p.read_bytes()!=data:raise RuntimeError('Existing project config differs; preserve and review')
            if not p.exists():p.write_bytes(data)
        outputs.append({'actor':actor,'source_config_verify':'PASS','entrypoint_probe':'PASS','source_files':len(value['files']),
            'workspace':str(workspace),'project_hooks_sha256':hashlib.sha256((dest/'hooks.json').read_bytes()).hexdigest(),
            'source_config_sha256':value['component_sha256'],'Native_owner_binding':'NOT_RUN','hook_trust':'PENDING_NATIVE_REVIEW'})
    profile,profile_root=native_runtime.verify(CONTROL/'native-profiles/LAB-A/profile.json')
    os.environ.update(native_runtime.environment(profile,profile_root))
    sys.path.insert(0,str(profile_root/'runtime'))
    spec=importlib.util.spec_from_file_location('lab_native_broker_metadata',profile_root/'runtime'/profile['broker'])
    broker=importlib.util.module_from_spec(spec);sys.modules[spec.name]=broker;spec.loader.exec_module(broker)
    facade=broker.UpstreamFacade([str(SSH),*upstream['args']],dict(os.environ),None,tools['tools'],
        {'protocolVersion':'2025-11-25','capabilities':{},'clientInfo':{'name':'LAB-technical-preflight','version':'1'}})
    try:
        actual=facade.request('tools/list',{},timeout=20)['tools']
        assert broker._tool_surface(actual)==broker._tool_surface(tools['tools'])
    finally:facade.close()
    save('native-profiles.json',{'status':'PREPARED_SOURCE_AND_ENTRYPOINTS_VERIFIED','actors':outputs,
        'actual_broker_upstream_contract_negotiation':'PASS','native_tools':len(actual),
        'models':'NOT_RUN','agents':'NOT_RUN','benchmarks':'NOT_RUN','live_lifecycle':'NOT_RUN'})


def bootstrap_ledgers():
    body=(CONTROL/'linux_backend.py').read_bytes()
    package={'body':base64.b64encode(body).decode('ascii'),'sha256':hashlib.sha256(body).hexdigest()}
    install=r'''
from pathlib import Path
import base64,hashlib,json,os,sys
assert os.geteuid()==0 and os.uname().nodename==@LINUX_HOSTNAME@
p=Path('/opt/integrity-lab/tools/linux_backend.py');assert p.is_file() and not p.is_symlink() and p.stat().st_uid==0
v=json.load(sys.stdin);body=base64.b64decode(v['body'],validate=True);assert hashlib.sha256(body).hexdigest()==v['sha256']
old=p.read_bytes()
if old!=body:
 # No configured preimage pin (null) means an existing different source is never replaced.
 assert hashlib.sha256(old).hexdigest()==@BACKEND_PREIMAGE@
 backup=p.with_name('linux_backend.py.before-explicit-turn-ledgers')
 if not backup.exists():backup.write_bytes(old);backup.chmod(0o600)
 temporary=p.with_name('linux_backend.py.native-ledger-stage');assert not temporary.exists()
 temporary.write_bytes(body);temporary.chmod(0o644);os.replace(temporary,p)
assert p.read_bytes()==body
print(json.dumps({'source_digest_verified':True,'source_sha256':v['sha256'],'previous_source_preserved':True}))
'''
    install=lab_config.fill(install,LINUX_HOSTNAME=lab_config.setting('vms.linux.hostname'),
        BACKEND_PREIMAGE=lab_config.setting('linux_guest.backend_migration_preimage_sha256',allow_null=True))
    deployed=json.loads(successful(remote('sudo -n /usr/bin/python3 -I -B -c '+shlex.quote(install),json.dumps(package))))
    result=json.loads(successful(remote('/opt/integrity-lab/venv/bin/python -I -B /opt/integrity-lab/tools/linux_backend.py --bootstrap-turn-memory')))
    save('native-ledger-bootstrap.json',{'status':'PASS','deployment':deployed,'bootstrap':result,'real_Native_owner_lifecycle':'NOT_RUN'})


def coverage():
    from integrity_client_memory import native_runtime
    broker,profile,root=load_profile_module('LAB-A','integrity-client-turn-broker.py','lab_isolated_coverage')
    config=tomllib.loads((root/'upstream.toml').read_text(encoding='utf-8'))['mcp_servers']['integrity-upstream']
    tools=broker._load_tools_contract(root/'integrity-client-tools.json')
    facade=broker.UpstreamFacade([config['command'],*config['args']],dict(os.environ),None,tools,
        {'protocolVersion':'2025-11-25','capabilities':{},'clientInfo':{'name':'LAB-coverage-metadata','version':'1'}})
    try:
        r=facade.request('tools/call',{'name':'integrity_turn_memory_coverage','arguments':{'limit':1}},timeout=25)
        assert r.get('isError') is not True
        value=json.loads(next(x['text'] for x in r['content'] if x['type']=='text'))
        assert value['complete'] and value['modern_creation_enabled'] and value['counts']['registered']==value['counts']['unresolved']==0
    finally:facade.close()
    active=successful(remote("systemctl list-units --no-legend --state=running,activating 'integrity-lab-mcp-*'"))
    assert not active.strip()
    save('native-isolated-coverage.json',{'status':'PASS','transport':'REAL_NATIVE_BROKER_FORCED_SSH_SYSTEMD_SANDBOX',
        'coverage_complete':value['complete'],'counts':value['counts'],'modern_creation_enabled':value['modern_creation_enabled'],
        'transient_MCP_units_remaining':0,'Native_owner_registration':'NOT_RUN','models':'NOT_RUN','agents':'NOT_RUN','benchmarks':'NOT_RUN'})


def load_profile_module(actor,filename,label):
    from integrity_client_memory import native_runtime
    profile,root=native_runtime.verify(CONTROL/'native-profiles'/actor/'profile.json')
    os.environ.update(native_runtime.environment(profile,root))
    for name in list(os.environ):
        if name.startswith('CODEX_') and name not in {'CODEX_HOME'}:os.environ.pop(name)
    sys.path.insert(0,str(root/'runtime'))
    spec=importlib.util.spec_from_file_location(label,root/'runtime'/filename)
    module=importlib.util.module_from_spec(spec);sys.modules[label]=module;spec.loader.exec_module(module)
    return module,profile,root


def guards():
    from integrity_client_memory import native_runtime
    rows=[]
    for actor in ['LAB-A','LAB-B']:
        # Explicitly protect the Native project config below the writable workspace.
        home=ROOT/'clients'/actor/'.codex';config=home/'config.toml';old=config.read_bytes()
        text=old.decode('utf-8').replace('\r\n','\n');entry="'"+str(ROOT/'workspaces'/actor/'.codex')+"' = \"read\"\n"
        if entry not in text:
            if text.count('[permissions.lab-role.filesystem]\n')!=1:raise RuntimeError('Expected role permission profile')
            backup=home/('config.before-native-protection.'+hashlib.sha256(old).hexdigest()[:12]+'.toml')
            if not backup.exists():backup.write_bytes(old)
            text=text.replace('[permissions.lab-role.filesystem]\n','[permissions.lab-role.filesystem]\n'+entry)
            tomllib.loads(text);config.write_text(text,encoding='utf-8')
        broker,profile,root=load_profile_module(actor,'integrity-client-turn-broker.py','lab_guard_broker_'+actor.replace('-','_'))
        before=sum(1 for _ in (root/'turn-envelopes').glob('*'))
        result,code=native_runtime.hook(profile,root,'UserPromptSubmit',json.dumps({
            'cwd':str(ROOT/'workspaces'/actor),'prompt':'Synthetic negative check: Native session and turn intentionally absent.'}).encode())
        blocked=bool(code or native_runtime.blocked(result))
        if not blocked:raise RuntimeError('Missing Native identities were not explicitly refused')
        target=broker.TurnBroker(root/'upstream.toml','integrity-upstream',broker._load_tools_contract(root/'integrity-client-tools.json'))
        checks=[]
        try:
            for name,arguments in [('integrity_context_admission_current_turn',{'turn_ref':'turnref:LAB-NEGATIVE-UNISSUED-REFERENCE000000000'}),('integrity_turn_memory_open',{}),('integrity_turn_memory_close',{})]:
                r=target.dispatch({'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':name,'arguments':arguments}})
                denied='error' in r or r.get('result',{}).get('isError') is True
                checks.append({'tool':name,'missing_owning_source_denied':denied})
                if not denied:raise RuntimeError('Unbound lifecycle call unexpectedly accepted')
        finally:target.close()
        assert before==sum(1 for _ in (root/'turn-envelopes').glob('*'))==0
        rows.append({'actor':actor,'missing_native_ID_hook':'REFUSED','unissued_or_unbound_calls':checks,
            'envelopes_created':0,'real_owner_identity_fabricated':False,'live_owner_lifecycle':'NOT_RUN'})
    source=r'''
import json,sqlite3,sys
sys.path.insert(0,'/opt/integrity-lab/tools')
import linux_backend
s=linux_backend.build();rows={}
for profile,path in s.turn_memory.paths.items():
 with sqlite3.connect(path.as_uri()+'?mode=ro',uri=True) as db:
  db.execute('PRAGMA query_only=ON')
  rows[profile]={table:db.execute('SELECT COUNT(*) FROM '+table).fetchone()[0] for table in ['turn_registrations','turn_terminal_receipts','turn_gap_receipts']}
print(json.dumps(rows))
'''
    ledger=json.loads(successful(remote('/opt/integrity-lab/venv/bin/python -I -B -',source)))
    assert all(v==0 for rows_ in ledger.values() for v in rows_.values())
    save('native-lifecycle-guards.json',{'status':'PASS_NEGATIVE_GUARDS_ONLY','actors':rows,'LAB_turn_ledger':ledger,
        'full_Native_owner_lifecycle':'NOT_RUN_REQUIRES_REAL_DESKTOP_OWNER_TURN','models':'NOT_RUN','agents':'NOT_RUN','benchmarks':'NOT_RUN'})


def host():
    import ctypes,msvcrt
    from ctypes import wintypes
    reader,_,_=load_profile_module('LAB-A','delegation-native-reader.py','lab_native_host_metadata')
    k=ctypes.WinDLL('kernel32',use_last_error=True)
    k.GetNamedPipeServerProcessId.argtypes=[wintypes.HANDLE,ctypes.POINTER(wintypes.ULONG)]
    k.OpenProcess.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.DWORD];k.OpenProcess.restype=wintypes.HANDLE
    k.QueryFullProcessImageNameW.argtypes=[wintypes.HANDLE,wintypes.DWORD,wintypes.LPWSTR,ctypes.POINTER(wintypes.DWORD)]
    k.CloseHandle.argtypes=[wintypes.HANDLE]
    rows=[]
    # The namespace fallback does not read any process environment or credentials.
    # Current Desktop has a dedicated app-tools pipe. The pinned public reader's
    # legacy fallback selects browser-use pipes, which use a different protocol.
    # This controller-only diagnostic does not patch the pinned Native runtime.
    candidates=['\\\\.\\pipe\\'+n for n in os.listdir('\\\\.\\pipe\\') if n.startswith('codex-app-tools-')]
    for pipe in candidates[:3]:
        with open(pipe,'r+b',buffering=0) as stream:
            pid=wintypes.ULONG()
            if not k.GetNamedPipeServerProcessId(msvcrt.get_osfhandle(stream.fileno()),ctypes.byref(pid)):raise OSError('Cannot bind pipe to its server process')
        handle=k.OpenProcess(0x1000,False,pid.value)
        if not handle:raise OSError('Cannot query Native host identity')
        try:
            size=wintypes.DWORD(32768);buf=ctypes.create_unicode_buffer(32768)
            if not k.QueryFullProcessImageNameW(handle,0,buf,ctypes.byref(size)):raise OSError('Native host process path unavailable')
            image=Path(buf.value)
            assert image.is_relative_to(Path('C:/Program Files/WindowsApps/OpenAI.Codex_26.1013.4894.0_x64__2p2nqsd0c76g0'))
        finally:k.CloseHandle(handle)
        result=reader.NativeAppHostRpc(pipe).request('tools/list',{'threadStartKind':'all'},15)
        definitions=result.get('tools')
        assert isinstance(definitions,list)
        names=[str(x.get('namespace',''))+'.'+str(x.get('name','')) for x in definitions]
        rows.append({'server_PID':pid.value,'server_image':str(image),'tools_list':'PASS','native_tool_count':len(definitions),
            'tool_names_only':names,
            'history_tool_surface':[x for x in names if x.rsplit('.',1)[-1] in {'read_thread','list_threads','list_archived_threads','read_page_reference'}],
            'model_facing_exposure':'NOT_TESTED_NO_MODEL_TURN',
            'working_thread_or_history_calls':0})
    save('native-desktop-host.json',{'status':'HOST_ENDPOINT_VERIFIED' if rows else 'NO_NATIVE_TOOL_PIPE',
        'hosts':rows,'owner_thread_turn_binding':'NOT_RUN_NO_NATIVE_OWNER_TURN','process_environment_read':False,
        'native_tasks_created':0,'models':'NOT_RUN','agents':'NOT_RUN','benchmarks':'NOT_RUN'})


def main():
    if os.name!='nt' or os.environ.get('COMPUTERNAME')!=lab_config.setting('vms.windows.hostname'):raise RuntimeError('Only Windows LAB guest')
    p=argparse.ArgumentParser();p.add_argument('stage',choices=['provision','sandbox','bindings','profiles','bootstrap_ledgers','guards','host','coverage']);args=p.parse_args()
    globals()[args.stage]()


if __name__=='__main__':main()

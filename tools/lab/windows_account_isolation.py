# SPDX-License-Identifier: BUSL-1.1
"""Guest-only account isolation policy; no login, task, model or history reads."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import queue
import subprocess
import threading
import time
import tomllib
import sys
sys.path.insert(0,str(Path(__file__).absolute().parent))
import lab_config

ROOT = Path('C:/IntegrityLAB')
CONTROL = ROOT/'control/preflight-labadmin'
POLICY = '''
[features]
apps = false
plugins = false
memories = false
[memories]
use_memories = false
generate_memories = false
[apps._default]
enabled = false
destructive_enabled = false
open_world_enabled = false
[plugins."codex-app-tools@openai-bundled"]
enabled = false
'''
APP_TOOLS_DENY = '''
[mcp_servers.codex_app]
enabled = false
command = ""
enabled_tools = []
[plugins."codex-app-tools@openai-bundled".mcp_servers.codex_app]
enabled = false
enabled_tools = []
'''


def guard():
    if os.name != 'nt' or os.environ.get('COMPUTERNAME') != lab_config.setting('vms.windows.hostname'):
        raise PermissionError('Exact LAB guest required')


def save(name, value):
    (ROOT/'evidence'/name).write_text(json.dumps(value, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(value))


def replace_config(path, text):
    old = path.read_bytes()
    digest = hashlib.sha256(old).hexdigest()
    backup = path.with_name(path.name+'.before-account-isolation.'+digest[:16])
    if not backup.exists():
        backup.write_bytes(old)
    parsed = tomllib.loads(text)
    assert parsed['features']['apps'] is False
    assert parsed['features']['plugins'] is False
    assert parsed['features']['memories'] is False
    assert parsed['memories'] == {'use_memories': False, 'generate_memories': False}
    assert parsed['apps']['_default']['enabled'] is False
    if old != text.encode('utf-8'):
        path.write_text(text, encoding='utf-8')
    assert tomllib.loads(path.read_text(encoding='utf-8')) == parsed
    return {'path':str(path), 'preimage_sha256':digest,
            'sha256':hashlib.sha256(path.read_bytes()).hexdigest(), 'backup':str(backup)}


def apply():
    desktop = Path.home()/'.codex/config.toml'
    before = tomllib.loads(desktop.read_text(encoding='utf-8'))
    # The exact preflighted default profile has desktop UI settings only.
    # Never silently overwrite a signed-in or unexpectedly configured profile.
    assert set(before) == {'desktop'}, 'Inspect unexpected guest config first'
    assert not (desktop.parent/'auth.json').exists(), 'Inspect existing guest sign-in first'
    old_text = desktop.read_text(encoding='utf-8')
    rows = [replace_config(desktop, old_text.rstrip()+'\n'+POLICY)]
    for actor in ['LAB-A','LAB-B']:
        path = ROOT/'clients'/actor/'.codex/config.toml'
        text = path.read_text(encoding='utf-8')
        old = tomllib.loads(text)
        assert old['features']['apps'] is False and old['features']['plugins'] is False
        assert old['features']['memories'] is False and old['agents']['enabled'] is False
        suffix = POLICY[POLICY.index('[memories]'):]
        rows.append(replace_config(path,text.rstrip()+'\n'+suffix))
    save('account-isolation-policy.json', {'schema':'integrity-lab.account-policy.v1',
        'status':'APPLIED_GUEST_LOCAL_ONLY','configs':rows,
        'account_global_settings_modified':False,'working_config_modified':False,
        'auth_files_read':False,'auth_files_copied':False,
        'cloud_chat_authorization_boundary':'NOT_VERIFIED',
        'models':'NOT_RUN','agents':'NOT_RUN','benchmarks':'NOT_RUN'})


def harden():
    prior=json.loads((ROOT/'evidence/account-isolation-policy.json').read_text(encoding='utf-8'))
    rows=[]
    for entry in prior['configs']:
        path=Path(entry['path'])
        assert hashlib.sha256(path.read_bytes()).hexdigest()==entry['sha256'], 'Guest config changed since applied receipt'
        text=path.read_text(encoding='utf-8')+APP_TOOLS_DENY
        if path.parent==Path.home()/'.codex':
            text='approval_policy = "never"\ndefault_permissions = "lab-desktop-closed"\nweb_search = "disabled"\n'+text
            text+='''
[agents]
enabled = false
[permissions.lab-desktop-closed.filesystem]
":root" = "deny"
":minimal" = "read"
[permissions.lab-desktop-closed.network]
enabled = false
'''
        rows.append(replace_config(path,text))
    save('account-isolation-hardened.json',{'status':'APPLIED_GUEST_LOCAL_ONLY','configs':rows,
        'ordinary_local_memories':'DISABLED_USE_AND_GENERATION','connectors':'DISABLED',
        'bundled_Desktop_tools':'DISABLED_BOTH_CONFIGURATION_ROUTES',
        'Desktop_default_execution':'DENY_ROOT_MINIMAL_READ_NO_NETWORK',
        'Native_Desktop_live_tool_denial':'NOT_VERIFIED',
        'account_global_settings_modified':False,'models':'NOT_RUN','agents':'NOT_RUN','benchmarks':'NOT_RUN'})


def control_read(cli, home, cwd, deny_routes=False):
    env = {k:v for k,v in os.environ.items() if not k.upper().startswith(
        ('CODEX_','INTEGRITY_','OPENAI_','ANTHROPIC_','AZURE_OPENAI'))}
    env['CODEX_HOME'] = str(home)
    process = subprocess.Popen([str(cli),'app-server'],cwd=cwd,env=env,
        stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
        text=True,encoding='utf-8',errors='replace')
    messages = queue.Queue()
    def read():
        for line in process.stdout:
            try: messages.put(json.loads(line))
            except ValueError: pass
    threading.Thread(target=read,daemon=True).start()
    def request(number, method, params):
        process.stdin.write(json.dumps({'id':number,'method':method,'params':params})+'\n')
        process.stdin.flush()
        deadline=time.monotonic()+25
        while time.monotonic()<deadline:
            message=messages.get(timeout=max(.1,deadline-time.monotonic()))
            if message.get('id')==number:
                if 'error' in message: raise RuntimeError('Control request refused: '+method+' '+str(message['error']))
                return message['result']
        raise TimeoutError(method)
    try:
        request(1,'initialize',{'clientInfo':{'name':'integrity-lab-account-preflight','version':'1'},'capabilities':{'experimentalApi':True}})
        process.stdin.write(json.dumps({'method':'initialized','params':{}})+'\n');process.stdin.flush()
        result=request(2,'config/read',{'includeLayers':False,'cwd':str(cwd)})
        writes=[]
        if deny_routes:
            paths=['mcp_servers.codex_app.enabled','mcp_servers.cua_repl.enabled','mcp_servers.node_repl.enabled',
                   'plugins."codex-app-tools@openai-bundled".enabled',
                   'plugins."codex-app-tools@openai-bundled".mcp_servers.codex_app.enabled']
            for index,key in enumerate(paths,10):
                request(index,'config/value/write',{'keyPath':key,'value':False,'mergeStrategy':'replace','filePath':str(home/'config.toml')})
                writes.append(key)
            result=request(30,'config/read',{'includeLayers':False,'cwd':str(cwd)})
        account=request(3,'account/read',{'refreshToken':False}).get('account')
        config=result['config']
        features=config.get('features',{})
        memories=config.get('memories',{})
        apps=config.get('apps',{})
        assert all(features.get(k) is False for k in ['apps','plugins','memories'])
        assert memories.get('use_memories') is False and memories.get('generate_memories') is False
        assert apps.get('_default',{}).get('enabled') is False
        return {'home':str(home),'cwd':str(cwd),'status':'PASS_CONFIG_READ_ONLY',
            'features':{k:features.get(k) for k in ['apps','plugins','memories']},
            'memories':{'use_memories':memories.get('use_memories'),'generate_memories':memories.get('generate_memories')},
            'apps_default_enabled':apps.get('_default',{}).get('enabled'),
            'bundled_app_tools_plugin_enabled':config.get('plugins',{}).get('codex-app-tools@openai-bundled',{}).get('enabled'),
            'MCP_names':list(config.get('mcp_servers',{})),
            'MCP_enabled_flags':{k:v.get('enabled',True) for k,v in config.get('mcp_servers',{}).items()},
            'codex_app_MCP_enabled':config.get('mcp_servers',{}).get('codex_app',{}).get('enabled'),
            'codex_app_enabled_tools':config.get('mcp_servers',{}).get('codex_app',{}).get('enabled_tools'),
            'default_permissions':config.get('default_permissions'),
            'account_authenticated':account is not None,
            'account_type':account.get('type') if account else None,
            'guest_only_native_config_API_writes':writes,
            'thread_creation':False,'model_turns':0}
    finally:
        if process.stdin: process.stdin.close()
        try: process.wait(timeout=5)
        except subprocess.TimeoutExpired: process.terminate();process.wait(timeout=5)


def verify(cli):
    rows=[]
    for actor in ['LAB-A','LAB-B']:
        workspace=ROOT/'workspaces'/actor
        rows.append(control_read(cli,ROOT/'clients'/actor/'.codex',workspace))
        rows.append(control_read(cli,Path.home()/'.codex',workspace))
    save('account-isolation-config-readback.json',{'status':'PASS_MEMORY_AND_CONNECTOR_CONFIG_ONLY','contexts':rows,
        'Native_Desktop_live_tool_denial':'NOT_VERIFIED','cloud_history_read':False,
        'account_memory_settings_modified':False,'models':'NOT_RUN','agents':'NOT_RUN','benchmarks':'NOT_RUN'})


def auth_sandbox(cli):
    auth=Path.home()/'.codex/auth.json'
    rows=[]
    if auth.is_file():
        code='''import sys
try:
 f=open(sys.argv[1],"rb");f.close()
 print("FAIL_AUTH_FILE_OPENABLE_NO_BYTES_READ")
 sys.exit(2)
except PermissionError:
 print("PASS_AUTH_FILE_OPEN_DENIED_NO_BYTES_READ")
'''
        for actor in ['LAB-A','LAB-B']:
            env={k:v for k,v in os.environ.items() if not k.upper().startswith(('CODEX_','INTEGRITY_','OPENAI_','ANTHROPIC_'))}
            env['CODEX_HOME']=str(ROOT/'clients'/actor/'.codex')
            try:
                p=subprocess.run([str(cli),'sandbox','--include-managed-config','--permission-profile','lab-role','--',
                    str(ROOT/'runtime/venv/Scripts/python.exe'),'-I','-B','-c',code,str(auth)],
                    cwd=ROOT/'workspaces'/actor,env=env,text=True,capture_output=True,timeout=45)
                rows.append({'actor':actor,'status':'PASS' if p.returncode==0 and p.stdout.strip()=='PASS_AUTH_FILE_OPEN_DENIED_NO_BYTES_READ' else 'FAIL',
                             'exit_code':p.returncode,'contents_read':False})
            except subprocess.TimeoutExpired:
                rows.append({'actor':actor,'status':'UNKNOWN_SANDBOX_STARTUP_TIMEOUT','contents_read':False})
    save('account-auth-sandbox.json',{'status':'PASS' if len(rows)==2 and all(x['status']=='PASS' for x in rows) else 'UNKNOWN_OR_FAIL',
         'auth_file_present':auth.is_file(),'claims':rows,'credential_contents_read':False,
         'models':'NOT_RUN','agents':'NOT_RUN','benchmarks':'NOT_RUN'})


if __name__ == '__main__':
    guard()
    parser=argparse.ArgumentParser()
    parser.add_argument('stage',choices=['apply','harden','verify','seal-native-tools','verify-desktop','probe-auth-sandbox'])
    parser.add_argument('--cli',type=Path)
    args=parser.parse_args()
    if args.stage=='apply': apply()
    elif args.stage=='harden': harden()
    else:
        cli=args.cli.resolve(strict=True)
        if not cli.is_relative_to(Path('C:/Program Files/WindowsApps')) or cli.name!='codex.exe':
            raise PermissionError('Expected packaged CLI')
        if args.stage=='seal-native-tools':
            result=control_read(cli,Path.home()/'.codex',ROOT/'workspaces/LAB-A',deny_routes=True)
            save('account-native-tool-policy.json',result)
        elif args.stage=='verify-desktop':
            result=control_read(cli,Path.home()/'.codex',ROOT/'workspaces/LAB-A')
            assert result['account_authenticated'] and result['account_type']=='chatgpt'
            assert not result['bundled_app_tools_plugin_enabled']
            assert all(result['MCP_enabled_flags'].get(k) is False for k in ['codex_app','node_repl','cua_repl'])
            save('account-desktop-final-readback.json',result)
        elif args.stage=='probe-auth-sandbox':auth_sandbox(cli)
        else:verify(cli)

# SPDX-License-Identifier: BUSL-1.1
"""Prepare reviewed LAB hook definitions and inspect native trust, without models."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import queue
import subprocess
import threading
import time
import sys
sys.path.insert(0,str(Path(__file__).absolute().parent))
import lab_config

ROOT=Path('C:/IntegrityLAB')
CONTROL=ROOT/'control/preflight-labadmin'
PROFILES=CONTROL/'native-profiles-compat-v3'
CLI=Path('C:/Program Files/WindowsApps/OpenAI.Codex_26.1013.4894.0_x64__2p2nqsd0c76g0/app/resources/codex.exe')


class Control:
    def __init__(self):
        env={k:v for k,v in os.environ.items() if not k.upper().startswith(('CODEX_','INTEGRITY_','OPENAI_','ANTHROPIC_'))}
        env['CODEX_HOME']=str(Path.home()/'.codex')
        self.proc=subprocess.Popen([str(CLI),'app-server'],cwd=ROOT,env=env,
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
            text=True,encoding='utf-8',errors='replace',bufsize=1)
        self.q=queue.Queue();self.counter=0
        def drain():
            for line in self.proc.stdout:
                try:self.q.put(json.loads(line))
                except ValueError:pass
            self.q.put(None)
        threading.Thread(target=drain,daemon=True).start()
        self.call('initialize',{'clientInfo':{'name':'IntegrityLAB-hook-review','version':'1'},'capabilities':{'experimentalApi':True}})
        self.proc.stdin.write('{"method":"initialized","params":{}}\n');self.proc.stdin.flush()

    def call(self,method,params):
        if method not in {'initialize','config/read','config/value/write','hooks/list'}:
            raise PermissionError('Only LAB configuration and hook metadata APIs')
        self.counter+=1;rid=self.counter
        self.proc.stdin.write(json.dumps({'id':rid,'method':method,'params':params})+'\n');self.proc.stdin.flush()
        deadline=time.monotonic()+25
        while time.monotonic()<deadline:
            row=self.q.get(timeout=max(.1,deadline-time.monotonic()))
            if row is None:raise RuntimeError('LAB metadata process exited')
            if row.get('id')==rid:
                if 'error' in row:raise RuntimeError('LAB metadata API refused '+method+' code '+str(row['error'].get('code')))
                return row['result']
        raise TimeoutError('LAB metadata API timeout')

    def close(self):
        self.proc.stdin.close()
        try:self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:self.proc.terminate();self.proc.wait(timeout=5)


def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def configure():
    from integrity_client_memory import native_runtime
    rows=[]
    backup=CONTROL/'before-compat-v3-hook-activation'
    backup.mkdir(exist_ok=True)
    session=Control()
    try:
        for actor in ['LAB-A','LAB-B']:
            native_runtime.verify(PROFILES/actor/'profile.json')
            cwd=ROOT/'workspaces'/actor
            old=CONTROL/'native-profiles-compat-v2'/actor/'codex-workspace/.codex'
            new=PROFILES/actor/'codex-workspace/.codex'
            receipt=[]
            for name in ['config.toml','hooks.json']:
                target=cwd/'.codex'/name
                current=target.read_bytes()
                if current not in { (old/name).read_bytes(), (new/name).read_bytes() }:
                    raise PermissionError('Unexpected LAB project hook/config preimage')
                saved=backup/(actor+'-'+name)
                if not saved.exists():saved.write_bytes(current)
                target.write_bytes((new/name).read_bytes())
                assert digest(target)==digest(new/name)
                receipt.append({'path':str(target),'sha256':digest(target),'preimage':str(saved)})
            key='projects.'+json.dumps(str(cwd))+'.trust_level'
            session.call('config/value/write',{'keyPath':key,'value':'trusted','mergeStrategy':'replace',
                'filePath':str(Path.home()/'.codex/config.toml')})
            config=session.call('config/read',{'cwd':str(cwd),'includeLayers':False})['config']
            assert config['features']['memories'] is False and config['features']['apps'] is False and config['features']['plugins'] is False
            assert all(config.get('mcp_servers',{}).get(x,{}).get('enabled') is False for x in ['codex_app','node_repl','cua_repl'])
            assert config['mcp_servers']['integrity_native'].get('enabled',True) is True
            rows.append({'actor':actor,'workspace':str(cwd),'project_layer':'TRUSTED_VIA_OFFICIAL_CONFIG_API',
                'files':receipt,'ordinary_memory_and_broad_tools':'DISABLED',
                'LAB_integrity_native':'ENABLED_IN_PROJECT_CONFIG','hook_trust':'REQUIRES_NATIVE_REVIEW'})
    finally:session.close()
    save('native-hook-activation.json',{'status':'PASS_LAB_PROJECT_CONFIG_ACTIVATED_HOOK_TRUST_NOT_BYPASSED',
        'actors':rows,'working_account_global_settings_changed':False,'working_config_changed':False,
        'direct_trust_database_writes':0,'hook_trust_bypass':False,'model_turns':0})
    inspect()


def inspect():
    session=Control()
    try:
        data=session.call('hooks/list',{'cwds':[str(ROOT/'workspaces'/x) for x in ['LAB-A','LAB-B']]})['data']
        for actor in ['LAB-A','LAB-B']:
            config=session.call('config/read',{'cwd':str(ROOT/'workspaces'/actor),'includeLayers':False})['config']
            assert all(config['features'].get(x) is False for x in ['memories','apps','plugins'])
            assert all(config.get('mcp_servers',{}).get(x,{}).get('enabled') is False for x in ['codex_app','node_repl','cua_repl'])
    finally:session.close()
    rows=[]
    for entry in data:
        actor=Path(entry['cwd']).name
        assert actor in {'LAB-A','LAB-B'}
        hooks=entry['hooks']
        for hook in hooks:
            assert hook['source']=='project' and not hook['isManaged']
            assert Path(hook['sourcePath']).is_relative_to(ROOT/'workspaces'/actor/'.codex')
            assert str(PROFILES/actor) in hook.get('command','')
        rows.append({'actor':actor,'workspace':entry['cwd'],'hook_count':len(hooks),
            'hooks':[{k:x.get(k) for k in ['eventName','currentHash','trustStatus','enabled','sourcePath','command']} for x in hooks],
            'errors_count':len(entry['errors']),'warnings_count':len(entry['warnings'])})
    assert len(rows)==2 and all(x['hook_count']==9 and not x['errors_count'] for x in rows)
    trusted=all(h['trustStatus']=='trusted' for row in rows for h in row['hooks'])
    save('native-hook-trust-readback.json',{'status':'PASS_TRUSTED' if trusted else 'PENDING_NATIVE_REVIEW',
        'actors':rows,'ordinary_memory_and_broad_tools':'DISABLED_IN_RESOLVED_CONFIG',
        'hook_trust_bypass':False,'model_turns':0,'working_history_calls':0})


def save(name,value):
    (ROOT/'evidence'/name).write_text(json.dumps(value,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(value))


if __name__=='__main__':
    if os.name!='nt' or os.environ.get('COMPUTERNAME')!=lab_config.setting('vms.windows.hostname'):raise PermissionError('Exact LAB guest required')
    parser=argparse.ArgumentParser();parser.add_argument('stage',choices=['configure','inspect'])
    args=parser.parse_args();globals()[args.stage]()

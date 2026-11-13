# SPDX-License-Identifier: BUSL-1.1
"""Native metadata and message-contract checks, with zero threads/turns."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).absolute().parent))
from runtime_common import ROOT,within
from native_peer import client,NativePeerGateway
import json
from jsonschema import Draft202012Validator

rows=[]
for actor in ['LAB-A','LAB-B']:
    home=ROOT/'runtime/codex-homes'/actor
    with client(home,'NATIVE-'+actor+'.log') as session:
        init=session.call('initialize',{'clientInfo':{'name':'integrity-lab-preflight','version':'1.0'},'capabilities':{'experimentalApi':True}})
        if 'error' in init:raise RuntimeError('native initialize failed: '+str(init['error']))
        session.notify('initialized')
        loaded=session.call('thread/loaded/list',{})
        if 'error' in loaded:raise RuntimeError('native loaded-list failed: '+str(loaded['error']))
        data=loaded['result'].get('data',loaded['result'].get('threadIds',[]))
        if data:raise RuntimeError('isolated home unexpectedly contains loaded threads')
        config=session.call('config/read',{'includeLayers':False,'cwd':str(ROOT/'runtime/probes'/actor)})
        if 'error' in config:raise RuntimeError('native config read failed: '+str(config['error']))
        effective=config['result'].get('config',config['result'])
        hooks=session.call('hooks/list',{'cwds':[str(ROOT/'runtime/probes'/actor)]})
        account=session.call('account/read',{'refreshToken':False})
        # Only booleans/key names are retained; account content/credentials are never logged.
        rows.append({'actor':actor,'initialize':'PASS','loaded_threads':0,'effective_config_keys':sorted(effective),
                     'configured_mcp_names':sorted((effective.get('mcp_servers') or {}).keys()),
                     'hooks_list_error':hooks.get('error'),'hooks_result_keys':sorted(hooks.get('result',{})),
                     'account_present':bool(account.get('result',{}).get('account')),'account_error':account.get('error'),
                     'threads_created':0,'model_turns_started':0})
policy=json.loads(within('controller/native-peer.json').read_text())
gateway=NativePeerGateway({},policy)
bindings={'LAB-A':{'episode_id':'technical-schema-only','thread_id':'schema-only-A','verified_native_thread':True},'LAB-B':{'episode_id':'technical-schema-only','thread_id':'schema-only-B','verified_native_thread':True}}
draft=gateway.draft('LAB-A','LAB-B','Synthetic contract probe; do not execute.',bindings)
schema=json.loads(within('runtime/app-server-schema/v2/TurnStartParams.json').read_text())
Draft202012Validator(schema).validate(draft['params'])
rejections=[]
for name,call in [('foreign_recipient',lambda:gateway.draft('LAB-A','working-thread','x',bindings)),('unbound_recipient',lambda:gateway.draft('LAB-A','LAB-B','x',{})),('model_start_without_owner_GO',lambda:gateway.send('LAB-A','LAB-B','x',bindings))]:
    try:call()
    except PermissionError:rejections.append(name)
    else:raise AssertionError('native boundary not enforced: '+name)
report={'status':'PASS','scope':'native initialization/configuration and real schema; no peer model delivery','actors':rows,'native_schema':'PASS','denied':rejections,'agents':'NOT_RUN','benchmarks':'NOT_RUN','peer_delivery':'NOT_RUN','full_native_integrity_owner_binding':'NOT_RUN'}
within('evidence/NATIVE-PREFLIGHT.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
print(json.dumps(report))

# SPDX-License-Identifier: BUSL-1.1
"""One bounded infrastructure gate in the new guest; zero intent/model calls."""
from pathlib import Path
import importlib.metadata, json, os, platform, subprocess, sys, traceback

sys.path.insert(0,str(Path(__file__).absolute().parent))
import lab_config

HOME=Path(lab_config.setting('linux_guest.home'))
INSTANCE=lab_config.setting('linux_guest.instance_id')
DEVICE=lab_config.setting('linux_guest.device_id')
GUEST_IP=lab_config.setting('network.linux_guest_ip')
PREFIX=lab_config.setting('network.prefix_length')
ROOT=HOME/'backend'
rows=[]
def gate(name, fn):
    try:
        detail=fn();rows.append({'check':name,'status':'PASS','detail':detail})
    except Exception as exc:
        rows.append({'check':name,'status':'FAIL','exception':type(exc).__name__,'reason':str(exc)[:300]})
        traceback.print_exc(file=sys.stderr)
def run(args,**kwargs):
    try:
        return subprocess.run(args,capture_output=True,text=True,timeout=120,check=True,**kwargs)
    except subprocess.CalledProcessError as exc:
        lines=exc.stderr.splitlines()
        raise RuntimeError('Guest child failed: '+(lines[-1][:300] if lines else 'no stderr')) from None
def identity():
    assert sys.platform=='linux' and os.geteuid()!=0
    assert Path.home()==HOME
    assert Path.home().stat().st_mode & 0o077 == 0
    return {'python':platform.python_version(),'kernel':platform.release(),'uid':os.geteuid()}
def network():
    routes=json.loads(run(['ip','-j','route']).stdout)
    assert not any(x.get('dst')=='default' for x in routes)
    addresses=json.loads(run(['ip','-j','address']).stdout)
    nonloop=[a for a in addresses if a['ifname']!='lo']
    assert len(nonloop)==1
    assert any(a.get('local')==GUEST_IP and a.get('prefixlen')==PREFIX for a in nonloop[0]['addr_info'])
    assert not list(Path('/media').glob('sf_*')) and not Path('/mnt/hgfs').exists()
    return {'default_route':False,'interfaces':[a['ifname'] for a in nonloop],'ip':GUEST_IP+'/'+str(PREFIX)}
def bootstrap():
    ROOT.mkdir(mode=0o700,exist_ok=True)
    previous=HOME/'preflight.json'
    if previous.exists():
        old=json.loads(previous.read_text())
        prior=next((x for x in old['checks'] if x['check']=='real_POSIX_Native_trust_bootstrap' and x['status']=='PASS'),None)
        if prior and old['versions']['integrity-guardian']==importlib.metadata.version('integrity-guardian'):
            from integrity_guardian.native_trust import NativeTrustStore
            genesis=NativeTrustStore(ROOT/'trust',instance_id=INSTANCE).verify_genesis()
            assert genesis['genesis_id']==prior['detail']['genesis_id']
            return {**prior['detail'],'execution':'REUSED_PASS_CURRENT_GENESIS_VERIFIED'}
    result=run([str(Path(sys.executable).parent/'guardian'),'native-trust-bootstrap','--state-root',str(ROOT/'trust'),
        '--instance-id',INSTANCE,'--device-id',DEVICE,
        '--architecture-root',str(ROOT/'architecture')])
    data=json.loads(result.stdout);assert data['ok'] and data['history_rewritten'] is False
    return {k:data[k] for k in ['ok','status','instance_id','genesis_id','trust_profile','history_rewritten']}
def mcp():
    frames=[{'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2025-11-25','capabilities':{},'clientInfo':{'name':'lab-infrastructure-preflight','version':'1'}}},
        {'jsonrpc':'2.0','method':'notifications/initialized'}, {'jsonrpc':'2.0','id':2,'method':'tools/list','params':{}}]
    result=run([sys.executable,'/opt/integrity-lab/tools/linux_backend.py','--stdio'],input=''.join(json.dumps(f)+'\n' for f in frames))
    responses=[json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    first=next(r for r in responses if r.get('id')==1);assert 'result' in first,first.get('error')
    listed=next(r for r in responses if r.get('id')==2);assert 'result' in listed,listed.get('error')
    names=sorted(t['name'] for t in listed['result']['tools'])
    assert 'integrity_context_admission' in names and 'integrity_turn_memory_close' in names,names
    return {'server':first['result']['serverInfo'],'tools':names,'initialize':'PASS','intent_admissions':0,'lifecycle_execution':'NOT_RUN'}

os.umask(0o077)
gate('unprivileged_private_guest_identity',identity)
gate('guest_internal_network_no_default_route',network)
gate('real_POSIX_Native_trust_bootstrap',bootstrap)
gate('real_MCP_initialize_and_native_tool_catalog',mcp)
report={'schema':'integrity-lab.linux-guest-preflight.v1','status':'FAIL' if any(r['status']=='FAIL' for r in rows) else 'PASS',
    'checks':rows,'versions':{p:importlib.metadata.version(p) for p in ['integrity-guardian','integrity-action-log','integrity-client-memory']},
    'agents':'NOT_RUN','models':'NOT_RUN','benchmarks':'NOT_RUN','full_native_owner_lifecycle':'NOT_RUN',
    'cross_VM_transport':'NOT_RUN','provider_egress':'NOT_CONFIGURED'}
(HOME/'preflight.json').write_text(json.dumps(report,indent=2)+'\n')
print('INTEGRITY_LAB_PREFLIGHT_JSON='+json.dumps(report,separators=(',',':')),flush=True)
raise SystemExit(0 if report['status']=='PASS' else 1)

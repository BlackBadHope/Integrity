# SPDX-License-Identifier: BUSL-1.1
"""Host controller for exactly one authorized LAB Native lifecycle canary.

No host network, production config or working credentials are changed. A finally
block stops the guest proxy and disconnects only the owned Linux NAT NIC.
"""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).absolute().parent))
import hashlib
import json
import argparse
import re
import shutil
from windows_guest_control import ROOT,copy_config,copy_to,run
from windows_vm_stage import require
import vmctl
import lab_config

CONTROL='C:\\IntegrityLAB\\control\\preflight-labadmin\\'
PYTHON=r'C:\IntegrityLAB\runtime\venv\Scripts\python.exe'


def guest_source(source,timeout=60):
    return require(run(PYTHON,['-I','-B','-c',source],timeout=timeout))


def main(attempt='v1',mode='native'):
    if re.fullmatch(r'[a-z0-9-]{1,32}',attempt) is None:raise ValueError('Invalid attempt label')
    assert mode in {'native','efficiency','efficiency-files'}
    is_benchmark=mode!='native'
    run_id='eff-20261021-files-01' if mode=='efficiency-files' else 'eff-20261021-smoke-01'
    evidence_dir=ROOT/'evidence'/run_id
    input_name='efficiency-files-input.json' if mode=='efficiency-files' else 'efficiency-smoke-input.json'
    benchmark_payload=None
    if is_benchmark:
        fixture=ROOT/'controller/efficiency-smoke-fixtures.json'
        spec=json.loads(fixture.read_text(encoding='utf-8'))
        retrieval=json.loads((ROOT/'evidence/eff-20261021-smoke-01/retrieval.json').read_text(encoding='utf-8'))
        assert retrieval['fixture_sha256']==hashlib.sha256(fixture.read_bytes()).hexdigest()
        evidence_dir.mkdir(exist_ok=True)
        assert not (evidence_dir/'model-runs.json').exists()
        if mode=='efficiency-files':
            queries=json.loads((ROOT/'evidence/eff-20261021-smoke-01/query-ab.json').read_text(encoding='utf-8'))
            retrieval={**retrieval,'run_id':run_id,'kind':'files',
                'cases':[{'id':c['id'],'recall':c['recall'],'retrieval_seconds':c['retrieval_seconds']} for c in queries['rows'] if c['variant']=='Q1-exact-task-id'],
                'source_retrieval_evidence':'evidence/eff-20261021-smoke-01/query-ab.json','retrieval_reused_from_exact_Q1_run':True}
            (evidence_dir/'retrieval.json').write_text(json.dumps(retrieval,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        recalled={c['id']:c for c in retrieval['cases']}
        benchmark_payload={'run_id':run_id,'kind':'files' if mode=='efficiency-files' else 'context','cases':[]}
        for c in spec['cases']:
            row={k:c[k] for k in ['id','task_id','task','corpus','corpus_sha256']}
            row.update(capsule=recalled[c['id']]['recall'],retrieval_seconds=recalled[c['id']]['retrieval_seconds'])
            if mode=='efficiency-files':row['kind']='files'
            benchmark_payload['cases'].append(row)
    for name in (['NATIVE-CANARY-RESULT.json','NATIVE-CANARY-COVERAGE.json','NATIVE-CANARY-CONTROLLER.json'] if mode=='native' else []):
        old=ROOT/'evidence'/name
        if old.is_file():
            backup=old.with_name(old.stem+'-before-'+attempt+'-'+hashlib.sha256(old.read_bytes()).hexdigest()[:12]+'.json')
            if not backup.exists():shutil.copy2(old,backup)
    for name in [vmctl.WINDOWS,vmctl.LINUX]:
        assert json.loads(vmctl.owned_info(name)['VMState'])=='running'
    policy_path=ROOT/'controller/egress.json'
    policy=json.loads(policy_path.read_text(encoding='utf-8'))
    assert policy['VM_UUID']==vmctl.UUIDS[vmctl.LINUX] and policy['MAC']==vmctl.EGRESS_MAC
    assert policy['uplink_active'] is False
    copy_config()
    for name in ['windows_native_canary.py','windows_native_compat_stage.py','windows_egress_setup.py']:
        copy_to(ROOT/'tools'/name,CONTROL+name)
    if is_benchmark:copy_to(ROOT/'tools/windows_efficiency_smoke.py',CONTROL+'windows_efficiency_smoke.py')
    if is_benchmark:
        payload_path=ROOT/'runtime/diagnostics'/input_name
        payload_raw=(json.dumps(benchmark_payload,ensure_ascii=False,indent=2)+'\n').encode()
        if payload_path.exists():assert payload_path.read_bytes()==payload_raw
        else:payload_path.write_bytes(payload_raw)
        copy_to(payload_path,CONTROL+payload_path.name)
        old=evidence_dir/'controller.json'
        if old.exists():shutil.copy2(old,old.with_name('controller-before-file-input-'+hashlib.sha256(old.read_bytes()).hexdigest()[:12]+'.json'))
    summary={'schema':'integrity-lab.bounded-run-controller.v2','status':'STARTING',
        'owner_intent':'Bounded LAB test run; required technical steps proceed without per-step prompts',
        'mode':mode,'full_pilot_execution':False,'max_canary_user_turns':8 if is_benchmark else 1,'production_changes':0,
        'working_config_changes':0,'steps':[]}
    link_changed=False
    try:
        summary['stage']='ENABLE_OWNED_NAT_LINK'
        vmctl.call(['controlvm',policy['VM_UUID'],'setlinkstate2','on']);link_changed=True
        print('LAB_NAT_LINK_ON',flush=True)
        summary['stage']='GUEST_EGRESS_UP'
        source="""
import sys,json
sys.path.insert(0,r'C:\\IntegrityLAB\\control\\preflight-labadmin')
from windows_native_binding import remote,successful
network='''import os,socket,subprocess,time,json
assert os.geteuid()==0 and socket.gethostname()==@HOSTNAME@
def call(args):return subprocess.run(args,check=True,capture_output=True,text=True).stdout
call(['/usr/sbin/ip','link','set','egress0','up'])
call(['/usr/bin/networkctl','reconfigure','egress0'])
for i in range(15):
 data=json.loads(call(['/usr/sbin/ip','-j','-4','addr','show','dev','egress0']))
 if any(a.get('local')==@NAT_ADDRESS@ for d in data for a in d.get('addr_info',[])):break
 if i==5:subprocess.run(['/usr/bin/networkctl','renew','egress0'],capture_output=True)
 time.sleep(1)
else:raise RuntimeError('Expected owned NAT address absent')
routes=json.loads(call(['/usr/sbin/ip','-j','-4','route','show','default']))
assert len(routes)==1 and routes[0].get('dev')=='egress0' and routes[0].get('gateway')==@NAT_GATEWAY@
assert open('/proc/sys/net/ipv4/ip_forward').read().strip()=='0'
print(json.dumps({'status':'EXPECTED_LAB_NAT_UP','forwarding':False}))'''
network_result=json.loads(successful(remote('sudo -n /usr/bin/python3 -I -B -',network,timeout=35)))
import windows_egress_setup
windows_egress_setup.start(max_seconds=600)
print(json.dumps({'status':'LAB_PROXY_ON_BOUNDED_600_SECONDS','network':network_result}))
"""
        source=lab_config.fill(source,HOSTNAME=lab_config.setting('vms.linux.hostname'),
            NAT_ADDRESS=lab_config.setting('egress_network.nat_address'),NAT_GATEWAY=lab_config.setting('egress_network.nat_gateway'))
        out=guest_source(source,75)
        summary['steps'].append(json.loads(out.splitlines()[-1]))
        policy['uplink_active']=True;policy['proxy_service']='ACTIVE_CANARY_600_SECONDS'
        policy_path.write_text(json.dumps(policy,indent=2)+'\n',encoding='utf-8')
        print('LAB_PROXY_READY',flush=True)
        summary['stage']='NATIVE_CLI_CANARY' if mode=='native' else 'EFFICIENCY_EIGHT_RUNS'
        if mode=='native':
            p=run(PYTHON,['-I','-B',CONTROL+'windows_native_canary.py','run','--attempt',attempt],timeout=225)
        else:
            p=run(PYTHON,['-I','-B',CONTROL+'windows_efficiency_smoke.py','--payload-file',CONTROL+input_name],timeout=515)
        result=json.loads(require(p).splitlines()[-1])
        result_path=ROOT/'evidence/NATIVE-CANARY-RESULT.json' if mode=='native' else evidence_dir/'model-runs.json'
        result_path.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        print(json.dumps({'mode':mode,'subject_status':result.get('status'),'model_runs':len(result.get('rows',[])) if is_benchmark else result.get('model_turns')}),flush=True)
        summary['canary_result']=str(result_path.relative_to(ROOT))
        summary['stage']='INDEPENDENT_BACKEND_COVERAGE'
        p=run(PYTHON,['-I','-B',CONTROL+'windows_native_compat_stage.py','post_coverage'],timeout=75)
        coverage=json.loads(require(p).splitlines()[-1])
        coverage_path=ROOT/'evidence/NATIVE-CANARY-COVERAGE.json' if mode=='native' else evidence_dir/'native-backend-unchanged.json'
        coverage_path.write_text(json.dumps(coverage,indent=2)+'\n',encoding='utf-8')
        summary['coverage']=coverage['counts'];summary['coverage_evidence']=coverage_path.relative_to(ROOT).as_posix()
        summary['status']='CANARY_EXECUTED_EVIDENCE_COLLECTED'
        print(json.dumps({'backend_coverage':coverage['counts'],'complete':coverage['coverage_complete']}),flush=True)
    except Exception as exc:
        summary['status']='FAILED_AT_'+summary.get('stage','UNKNOWN')
        summary['error_type']=type(exc).__name__
        summary['safe_reason']=str(exc)[:250] if type(exc) in {RuntimeError,AssertionError,FileExistsError} else None
        print(json.dumps({'status':summary['status'],'error_type':summary['error_type'],'safe_reason':summary['safe_reason']}),flush=True)
    finally:
        try:
            source="""
import sys,json
sys.path.insert(0,r'C:\\IntegrityLAB\\control\\preflight-labadmin')
from windows_native_binding import remote,successful
commands='''import subprocess,json,os,socket
assert os.geteuid()==0 and socket.gethostname()==@HOSTNAME@
for args in [['/usr/bin/systemctl','stop','integrity-lab-egress.service'],['/usr/bin/networkctl','down','egress0'],['/usr/sbin/ip','-4','route','flush','dev','egress0'],['/usr/sbin/ip','-4','addr','flush','dev','egress0'],['/usr/sbin/ip','link','set','egress0','down']]:
 subprocess.run(args,capture_output=True,timeout=20)
state=subprocess.run(['/usr/bin/systemctl','is-active','integrity-lab-egress.service'],capture_output=True,text=True).stdout.strip()
assert state in {'inactive','unknown','failed'}
routes=json.loads(subprocess.check_output(['/usr/sbin/ip','-j','-4','route','show','default']))
assert not routes
addr=json.loads(subprocess.check_output(['/usr/sbin/ip','-j','-4','addr','show','dev','egress0']))
assert not any(x.get('addr_info') for x in addr)
print(json.dumps({'proxy':'STOPPED','proxy_service_state':state,'guest_egress_interface':'DOWN','default_routes':0}))'''
print(successful(remote('sudo -n /usr/bin/python3 -I -B -',commands,timeout=35)))
"""
            source=lab_config.fill(source,HOSTNAME=lab_config.setting('vms.linux.hostname'))
            summary['guest_cleanup']=json.loads(guest_source(source,45).splitlines()[-1])
        except Exception as exc:summary['guest_cleanup_error']=type(exc).__name__
        finally:
            if link_changed:
                vmctl.call(['controlvm',policy['VM_UUID'],'setlinkstate2','off'])
            policy['uplink_active']=False;policy['proxy_service']='STOPPED'
            policy_path.write_text(json.dumps(policy,indent=2)+'\n',encoding='utf-8')
        summary['NAT_cable']='OFF';summary['automatic_cleanup_scope']='Only owned LAB Linux egress0 and transient proxy'
        controller_path=ROOT/'evidence/NATIVE-CANARY-CONTROLLER.json' if mode=='native' else evidence_dir/'controller.json'
        controller_path.write_text(json.dumps(summary,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        print(json.dumps({'controller_status':summary['status'],'cleanup':summary.get('guest_cleanup'),'NAT_cable':'OFF'}),flush=True)


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--attempt',default='v1');parser.add_argument('--mode',choices=['native','efficiency','efficiency-files'],default='native')
    args=parser.parse_args();main(args.attempt,args.mode)

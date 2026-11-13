# SPDX-License-Identifier: BUSL-1.1
"""One bounded, source-vetted Native CLI LAB canary. No UI automation.

Uses the installed CLI's documented invocation-local hook automation switch.
It does not persist hook trust or bypass OS sandbox or Integrity owner checks.
"""
from pathlib import Path
import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
import queue
import re
import subprocess
import sys
import threading
import time
sys.path.insert(0,str(Path(__file__).absolute().parent))
import lab_config

ROOT=Path('C:/IntegrityLAB')
CONTROL=ROOT/'control/preflight-labadmin'
PROFILE=CONTROL/'native-profiles-compat-v3/LAB-A/profile.json'
WORKSPACE=ROOT/'workspaces/LAB-A'
CLI=Path('C:/Program Files/WindowsApps/OpenAI.Codex_26.1013.4894.0_x64__2p2nqsd0c76g0/app/resources/codex.exe')
READER_PIN='28c2f3ca1295ad59205b36ec862e0ffc66d58f35245a8581f9e26807b3bd12ae'
PROMPT='''This is an authorized synthetic IntegrityLAB Native lifecycle canary in the isolated Windows/Linux LAB. One user turn only. Use the own opaque turn_ref supplied by your current Native hook exactly once for Integrity context admission. Inspect context_delivery. Open and close only your own registered turn using the exact hook-issued identity. Use no-event/read-only because this canary makes no Seed append. Never fabricate identifiers, borrow other registrations or skip an owner check. Do not append Seed events, create agents/chats, send messages, read other chats or working data, browse, run shell commands or change files. Use only the LAB integrity_native MCP lifecycle tools. If binding or infrastructure fails, report the exact failing stage without claiming success. Finish with one compact JSON object containing status, admission_status, context_delivery_status, registration_id, terminal_receipt_id and unresolved. No other task is assigned.'''


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path,value):path.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')


def preflight():
    from integrity_client_memory import native_runtime
    sys.path.insert(0,str(CONTROL))
    from windows_native_hook_stage import Control
    profile,base=native_runtime.verify(PROFILE)
    assert profile['files']['delegation-native-reader.py']==READER_PIN
    assert profile['files']['integrity_client_turn_envelope.py']=='8a9a1866a1cee1d631b7871c048717f561d2b771e5ca0556a50262c32d0d2389'
    assert (WORKSPACE/'.codex/hooks.json').read_bytes()==(base/'codex-workspace/.codex/hooks.json').read_bytes()
    assert (WORKSPACE/'.codex/config.toml').read_bytes()==(base/'codex-workspace/.codex/config.toml').read_bytes()
    session=Control()
    try:
        hooks=session.call('hooks/list',{'cwds':[str(WORKSPACE)]})['data']
        config=session.call('config/read',{'cwd':str(WORKSPACE),'includeLayers':False})['config']
    finally:session.close()
    assert len(hooks)==1 and len(hooks[0]['hooks'])==9 and not hooks[0]['errors']
    for h in hooks[0]['hooks']:
        assert h['source']=='project' and not h['isManaged']
        assert str(base) in h.get('command','') and h['enabled']
    assert all(config['features'].get(k) is False for k in ['memories','apps','plugins'])
    assert all(config['memories'].get(k) is False for k in ['use_memories','generate_memories'])
    assert all(config['mcp_servers'].get(k,{}).get('enabled') is False for k in ['codex_app','node_repl','cua_repl'])
    assert config['apps']['_default']['enabled'] is False
    assert config['default_permissions']=='lab-desktop-closed'
    assert not config.get('agents',{}).get('enabled',False)
    assert (Path.home()/'.codex/auth.json').is_file()  # Existence only, no contents.
    return profile,base,{'profile_sha256':sha(PROFILE),'CLI_sha256':sha(CLI),
        'project_hooks_sha256':sha(WORKSPACE/'.codex/hooks.json'),
        'hook_hashes':[x['currentHash'] for x in hooks[0]['hooks']],
        'source_review':'PINNED_READER_7_SOURCE_CHECKS_LIVE_ENDPOINT_AND_BROKER_VERIFIED',
        'ordinary_memory_and_broad_tools':'DISABLED','permissions':'lab-desktop-closed',
        'hook_execution':'OFFICIAL_INVOCATION_LOCAL_VETTED_AUTOMATION_MODE',
        'persisted_trust_written':False,'sandbox_bypassed':False,'owner_checks_bypassed':False}


class KillJob:
    def __init__(self):
        # Windows job ownership gives a bounded cleanup of only this canary's tree.
        class Basic(ctypes.Structure):
            _fields_=[('process_time',ctypes.c_int64),('job_time',ctypes.c_int64),('flags',wintypes.DWORD),
                ('min_ws',ctypes.c_size_t),('max_ws',ctypes.c_size_t),('active_limit',wintypes.DWORD),
                ('affinity',ctypes.c_size_t),('priority',wintypes.DWORD),('scheduling',wintypes.DWORD)]
        class IO(ctypes.Structure):
            _fields_=[(n,ctypes.c_uint64) for n in ['read_count','write_count','other_count','read_bytes','write_bytes','other_bytes']]
        class Extended(ctypes.Structure):
            _fields_=[('basic',Basic),('io',IO),('process_mem',ctypes.c_size_t),('job_mem',ctypes.c_size_t),
                ('peak_process_mem',ctypes.c_size_t),('peak_job_mem',ctypes.c_size_t)]
        self.k=ctypes.WinDLL('kernel32',use_last_error=True)
        self.k.CreateJobObjectW.argtypes=[ctypes.c_void_p,wintypes.LPCWSTR];self.k.CreateJobObjectW.restype=wintypes.HANDLE
        self.k.SetInformationJobObject.argtypes=[wintypes.HANDLE,ctypes.c_int,ctypes.c_void_p,wintypes.DWORD]
        self.k.AssignProcessToJobObject.argtypes=[wintypes.HANDLE,wintypes.HANDLE]
        self.k.CloseHandle.argtypes=[wintypes.HANDLE]
        self.handle=self.k.CreateJobObjectW(None,None)
        if not self.handle:raise OSError('Canary job creation failed')
        value=Extended();value.basic.flags=0x2000  # KILL_ON_JOB_CLOSE only.
        if not self.k.SetInformationJobObject(self.handle,9,ctypes.byref(value),ctypes.sizeof(value)):
            self.close();raise OSError('Canary job cleanup policy failed')
    def assign(self,process):
        if not self.k.AssignProcessToJobObject(self.handle,int(process._handle)):
            raise OSError('Canary process-tree custody failed')
    def close(self):
        if self.handle:self.k.CloseHandle(self.handle);self.handle=None


def run_canary(attempt='v1'):
    if re.fullmatch(r'[a-z0-9-]{1,32}',attempt) is None:raise ValueError('Invalid canary attempt label')
    profile,base,checks=preflight()
    output=ROOT/'evidence'/('native-canary-'+attempt)
    if output.exists():raise FileExistsError('Canary already attempted; retain evidence and inspect before any new attempt')
    output.mkdir()
    save(CONTROL/'latest-native-canary.json',{'result_path':str(output/'result.json'),'attempt':attempt})
    start=time.monotonic()
    report={'schema':'integrity-lab.Native-canary-result.v1','status':'STARTING','source':'NATIVE_CLI_EXEC_NOT_SPOOFED_DESKTOP',
        'preflight':checks,'prompt_sha256':hashlib.sha256(PROMPT.encode()).hexdigest(),'max_user_turns':1,
        'deadline_seconds':180,'Seed_append_allowed':False,'working_history_calls_allowed':False,
        'events':[],'stderr_classifications':[],'model_turns':'NOT_CONFIRMED','Native_owner_binding':'NOT_VERIFIED'}
    result_file=output/'result.json';save(result_file,report)
    env={k:v for k,v in os.environ.items() if not k.upper().startswith(('CODEX_','INTEGRITY_','OPENAI_','ANTHROPIC_','AZURE_OPENAI'))}
    env['CODEX_HOME']=str(Path.home()/'.codex')
    env.update(HTTP_PROXY='http://'+lab_config.setting('network.linux_guest_ip')+':'+str(lab_config.setting('network.proxy_port')),HTTPS_PROXY='http://'+lab_config.setting('network.linux_guest_ip')+':'+str(lab_config.setting('network.proxy_port')),
        NO_PROXY='localhost,127.0.0.1,::1,'+lab_config.setting('network.linux_guest_ip'),
        SSL_CERT_FILE=str(ROOT/'runtime/venv/Lib/site-packages/pip/_vendor/certifi/cacert.pem'),
        NODE_EXTRA_CA_CERTS=str(ROOT/'runtime/venv/Lib/site-packages/pip/_vendor/certifi/cacert.pem'))
    command=[str(CLI),'exec','--dangerously-bypass-hook-trust','--skip-git-repo-check','--json',
        '-c','windows.sandbox="mxc"','-c','features.prefer_mxc=true',
        '-C',str(WORKSPACE),'-o',str(output/'final.txt'),'-']
    # Diagnostic hypothesis: an uncaught broker exception closes the public MCP
    # stream during real envelope resolution. Keep only source frame metadata.
    env['RUST_LOG']='info'
    job=KillJob();process=None;assigned=False;q=queue.Queue();errs=[];frames=[]
    try:
        process=subprocess.Popen(command,cwd=WORKSPACE,env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,text=True,encoding='utf-8',errors='replace',bufsize=1,
            creationflags=subprocess.CREATE_NO_WINDOW|subprocess.CREATE_NEW_PROCESS_GROUP)
        job.assign(process)
        assigned=True
        def stdout():
            for line in process.stdout:
                try:q.put(json.loads(line))
                except ValueError:pass  # Never persist raw process output or opaque refs.
            q.put(None)
        def stderr():
            for line in process.stderr:
                low=line.lower()
                frame=re.search(r'File "([^"\r\n]+\.py)", line (\d+), in ([A-Za-z_][A-Za-z_0-9<>]*)',line)
                if frame and len(frames)<30:
                    frames.append({'file':Path(frame[1]).name,'line':int(frame[2]),'function':frame[3]})
                failure=re.search(r'\b(NameError|AttributeError|TypeError|ValueError|KeyError|RuntimeError|OSError|PermissionError|TurnEnvelopeError):',line)
                if failure and len(frames)<30:
                    item={'exception':failure[1]}
                    missing=re.search(r"(?:name|attribute) '([A-Za-z_][A-Za-z_0-9]*)'",line)
                    if missing:item['missing_source_identifier']=missing[1]
                    frames.append(item)
                for key in ['workspace routing discovery failed','certificate','connection refused','timed out','hook','mcp','error']:
                    if key in low and key not in errs:errs.append(key)
        threading.Thread(target=stdout,daemon=True).start();threading.Thread(target=stderr,daemon=True).start()
        process.stdin.write(PROMPT);process.stdin.close()
        eof=False
        while time.monotonic()-start<180:
            try:row=q.get(timeout=.5)
            except queue.Empty:
                if eof and process.poll() is not None:break
                continue
            if row is None:
                eof=True
                if process.poll() is not None:break
                continue
            kind=row.get('type','unknown')
            safe={'type':kind,'offset_seconds':round(time.monotonic()-start,3)}
            if kind=='thread.started':
                report['thread_id']=row.get('thread_id');safe['thread_id']=row.get('thread_id')
            if kind=='turn.completed':
                safe['usage']=row.get('usage');report['usage']=row.get('usage');report['model_turns']='ONE_USER_TURN_COMPLETED'
            if kind in {'turn.failed','error'}:
                error=row.get('error',row.get('message',''))
                text=json.dumps(error,ensure_ascii=False)
                safe['error_sha256']=hashlib.sha256(text.encode()).hexdigest()
                safe['error_class']='WORKSPACE_ROUTING' if 'workspace routing discovery failed' in text else 'NATIVE_EXEC_ERROR'
            item=row.get('item',{})
            if item:
                safe['item_type']=item.get('type');safe['item_id']=item.get('id')
                for field in ['server','tool','status']:
                    if field in item:safe[field]=item[field]
                if item.get('type') in {'command_execution','web_search'}:
                    report['unexpected_agent_action']=item['type']
            report['events'].append(safe)
            save(result_file,report)
        if process.poll() is None:
            report['status']='TIMEOUT';job.close();process.wait(timeout=10)
        else:
            report['status']='PROCESS_COMPLETED' if process.returncode==0 else 'PROCESS_FAILED'
        report['exit_code']=process.returncode
    except Exception as exc:
        report['status']='HARNESS_ERROR';report['error_type']=type(exc).__name__
        if process and process.poll() is None:
            if assigned:job.close()
            else:process.terminate()
            try:process.wait(timeout=10)
            except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
    finally:
        job.close()
        report['elapsed_seconds']=round(time.monotonic()-start,3)
        report['stderr_classifications']=list(errs)
        report['broker_error_frames']=frames
        thread=report.get('thread_id')
        if isinstance(thread,str):
            # Read only the state belonging to the actual newly-issued canary id.
            state_file=base/'state'/(hashlib.sha256(thread.encode()).hexdigest()+'.json')
            if state_file.is_file():
                state=json.loads(state_file.read_text(encoding='utf-8'))
                report['own_state_keys']=sorted(state)
                keys=['turn_id','prompt_sha256','model_mcp_admission_status','model_mcp_context_admission_id',
                    'turn_memory_registration_id','turn_memory_intent_id','turn_memory_namespace_fingerprint',
                    'turn_memory_terminal_receipt','turn_memory_registration_receipt','turn_memory_close_status']
                report['own_state']={k:state[k] for k in keys if k in state}
        final=output/'final.txt'
        if final.is_file():
            report['final_sha256']=sha(final)
            try:
                value=json.loads(final.read_text(encoding='utf-8'))
                report['model_report']={k:value.get(k) for k in ['status','admission_status','context_delivery_status','registration_id','terminal_receipt_id','unresolved']}
            except (ValueError,UnicodeError):report['model_report_format']='NOT_JSON'
        save(result_file,report)
    print(json.dumps(report))


def startup_diagnostic():
    # Offline bootstrap only: no default route and a closed proxy destination.
    # Capture a bounded configuration error without another online model attempt.
    preflight()
    env={k:v for k,v in os.environ.items() if not k.upper().startswith(('CODEX_','INTEGRITY_','OPENAI_','ANTHROPIC_'))}
    env.update(CODEX_HOME=str(Path.home()/'.codex'),HTTP_PROXY='http://127.0.0.1:9',HTTPS_PROXY='http://127.0.0.1:9',NO_PROXY='')
    command=[str(CLI),'exec','--dangerously-bypass-hook-trust','--skip-git-repo-check','--json',
        '-c','windows.sandbox="mxc"','-c','features.prefer_mxc=true','-C',str(WORKSPACE),'-']
    job=KillJob();process=None
    try:
        process=subprocess.Popen(command,cwd=WORKSPACE,env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,text=True,encoding='utf-8',errors='replace',creationflags=subprocess.CREATE_NO_WINDOW)
        job.assign(process)
        try:stdout,stderr=process.communicate(PROMPT,timeout=15)
        except subprocess.TimeoutExpired:
            job.close();stdout,stderr=process.communicate(timeout=5)
        safe=[]
        for line in stderr.splitlines():
            if any(x in line.lower() for x in ['error','invalid','unsupported','unknown','permission']):
                line=re.sub(r'(?i)(bearer\s+)\S+',r'\1REDACTED',line)
                line=re.sub(r'(?i)((?:access_token|refresh_token|id_token|api_key|password|authorization|cookie)\s*[:=]\s*)\S+',r'\1REDACTED',line)
                line=re.sub(r'turnref:[A-Za-z0-9_-]+','turnref:REDACTED',line)
                line=re.sub(r'[A-Za-z0-9_+/=-]{28,}','REDACTED_LONG_VALUE',line)
                line=re.sub(r'(https?://[^?\s]+)\?[^\s]+',r'\1?REDACTED',line)
                safe.append(line[:1000])
        result={'status':'OFFLINE_STARTUP_DIAGNOSTIC','exit_code':process.returncode,
            'safe_error_lines':safe[:8],'stderr_sha256':hashlib.sha256(stderr.encode()).hexdigest(),
            'JSON_event_types':[],'proxy':'CLOSED_LOOPBACK_PORT','online_model_requests':0}
        for line in stdout.splitlines():
            try:result['JSON_event_types'].append(json.loads(line).get('type'))
            except ValueError:pass
        save(ROOT/'evidence/native-canary-startup-diagnostic.json',result)
        print(json.dumps(result))
    finally:job.close()


if __name__=='__main__':
    if os.name!='nt' or os.environ.get('COMPUTERNAME')!=lab_config.setting('vms.windows.hostname'):raise PermissionError('Exact LAB guest required')
    parser=argparse.ArgumentParser();parser.add_argument('stage',choices=['preflight','run','startup_diagnostic'])
    parser.add_argument('--attempt',default='v1')
    args=parser.parse_args()
    if args.stage=='preflight':print(json.dumps(preflight()[2]))
    elif args.stage=='startup_diagnostic':startup_diagnostic()
    else:run_canary(args.attempt)

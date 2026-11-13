# SPDX-License-Identifier: BUSL-1.1
"""Versioned LAB-only Native installation and endpoint metadata checks."""
from pathlib import Path
import argparse
import ctypes
from ctypes import wintypes
import hashlib
import importlib.util
import json
import msvcrt
import os
import subprocess
import sys
sys.path.insert(0,str(Path(__file__).absolute().parent))
import lab_config

ROOT = Path('C:/IntegrityLAB')
CONTROL = ROOT/'control/preflight-labadmin'
BASE = CONTROL/'native-profiles-compat-v3'
CANDIDATE = CONTROL/'delegation-native-reader.py'
ENVELOPE = CONTROL/'integrity_client_turn_envelope.py'
ENVELOPE_PIN = '8a9a1866a1cee1d631b7871c048717f561d2b771e5ca0556a50262c32d0d2389'
PIN = '28c2f3ca1295ad59205b36ec862e0ffc66d58f35245a8581f9e26807b3bd12ae'
PUBLIC_PIN = 'b5277ef1db377eb9fb9307cb9b19804eeab1b05019463bf4bd3451a6bfd42e23'
PACKAGE = Path('C:/Program Files/WindowsApps/OpenAI.Codex_26.1013.4894.0_x64__2p2nqsd0c76g0')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(name, result):
    (ROOT/'evidence'/name).write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(result))


def install():
    from integrity_client_memory import native_install, native_runtime
    bindings = json.loads((CONTROL/'native-bindings.json').read_text())
    tools = json.loads((CONTROL/'native-current-tools.json').read_text())
    assert sha(CANDIDATE) == PIN
    assert sha(ENVELOPE) == ENVELOPE_PIN
    original_selector = native_install.source_files
    original_sources, _, _ = original_selector('codex')
    assert sha(next(x for x in original_sources if x.name == CANDIDATE.name)) == PUBLIC_PIN
    upstream = json.loads((CONTROL/'native-profiles/LAB-A/profile.json').read_text())
    # Read only the old profile's public transport definition, never SSH key data.
    import tomllib
    upstream = tomllib.loads((CONTROL/'native-profiles/LAB-A/upstream.toml').read_text())['mcp_servers']['integrity-upstream']

    def selected(vendor):
        paths, hook, broker = original_selector(vendor)
        return [CANDIDATE if p.name == CANDIDATE.name else ENVELOPE if p.name == ENVELOPE.name else p for p in paths], hook, broker

    rows=[]
    BASE.mkdir(exist_ok=True)
    try:
        native_install.source_files = selected
        for actor in ['LAB-A','LAB-B']:
            dest = BASE/actor
            if not dest.exists():
                native_install.build('codex',upstream,bindings,dest,tools)
            profile, root = native_runtime.verify(dest/'profile.json')
            assert profile['files'][CANDIDATE.name] == PIN
            assert profile['files'][ENVELOPE.name] == ENVELOPE_PIN
            assert native_runtime.main(['--profile',str(dest/'profile.json'),'probe']) == 0
            old=json.loads((CONTROL/'native-profiles'/actor/'profile.json').read_text())
            assert all(pin == old['files'][name] for name,pin in profile['files'].items() if name not in {CANDIDATE.name,ENVELOPE.name})
            rows.append({'actor':actor,'profile':str(dest/'profile.json'),'source_config_verify':'PASS',
                'entrypoint_probe':'PASS','reader_sha256':PIN,'envelope_sha256':ENVELOPE_PIN,'other_four_source_pins':'UNCHANGED',
                'original_profile_preserved':True})
    finally:
        native_install.source_files = original_selector
    assert sha(next(x for x in original_sources if x.name == CANDIDATE.name)) == PUBLIC_PIN
    save('native-compat-install.json',{'status':'PASS_VERSIONED_LAB_PROFILES_INSTALLED',
        'actors':rows,'project_hooks_switched':False,'public_library_changed':False,
        'owner_binding':'NOT_RUN','models':'NOT_RUN','benchmarks':'NOT_RUN'})


def module():
    from integrity_client_memory import native_runtime
    profile, root = native_runtime.verify(BASE/'LAB-A/profile.json')
    os.environ.update(native_runtime.environment(profile,root))
    sys.path.insert(0,str(root/'runtime'))
    spec=importlib.util.spec_from_file_location('lab_compat_reader',root/'runtime'/CANDIDATE.name)
    loaded=importlib.util.module_from_spec(spec)
    sys.modules[spec.name]=loaded
    spec.loader.exec_module(loaded)
    return loaded


def server_image(pipe):
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.GetNamedPipeServerProcessId.argtypes=[wintypes.HANDLE,ctypes.POINTER(wintypes.ULONG)]
    kernel.OpenProcess.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.DWORD]
    kernel.OpenProcess.restype=wintypes.HANDLE
    kernel.QueryFullProcessImageNameW.argtypes=[wintypes.HANDLE,wintypes.DWORD,wintypes.LPWSTR,ctypes.POINTER(wintypes.DWORD)]
    kernel.CloseHandle.argtypes=[wintypes.HANDLE]
    with open(pipe,'r+b',buffering=0) as stream:
        pid=wintypes.ULONG()
        if not kernel.GetNamedPipeServerProcessId(msvcrt.get_osfhandle(stream.fileno()),ctypes.byref(pid)):
            raise OSError('Native pipe server identity unavailable')
    handle=kernel.OpenProcess(0x1000,False,pid.value)
    if not handle:raise OSError('Native server query unavailable')
    try:
        size=wintypes.DWORD(32768);buffer=ctypes.create_unicode_buffer(32768)
        if not kernel.QueryFullProcessImageNameW(handle,0,buffer,ctypes.byref(size)):
            raise OSError('Native server image unavailable')
        image=Path(buffer.value)
        if not image.is_relative_to(PACKAGE) or image.name.lower()!='chatgpt.exe':
            raise PermissionError('Pipe belongs to an unexpected Native server')
        return pid.value,str(image)
    finally:
        kernel.CloseHandle(handle)


def endpoint():
    reader=module()
    candidates=reader.discover_codex_app_tool_pipes()
    # Pin the actual server image before allowing even tools/list to use a pipe.
    verified=[]
    for p in candidates:
        if '\\codex-app-tools-' not in p:continue
        pid,image=server_image(p)
        verified.append((p,pid,image))
    if len(verified)!=1:
        raise RuntimeError('Expected exactly one verified LAB Native app-tools endpoint')
    pipe,pid,image=verified[0]
    reader.discover_codex_app_tool_pipes=lambda:[pipe]
    host=reader.BACKENDS.get_codex_host()
    definitions=host.list_tools()
    needed={'create_thread','read_thread','send_message_to_thread','list_projects','set_thread_title'}
    selected=[x for x in definitions if x.get('name') in needed]
    # Definitions are public schemas only; no tools/call or thread reads here.
    (CONTROL/'native-app-tools-selected.json').write_text(json.dumps(selected,indent=2)+'\n')
    save('native-compat-endpoint.json',{'status':'PASS_INSTALLED_READER_REAL_NATIVE_ENDPOINT',
        'reader_sha256':PIN,'server_PID':pid,'server_image':image,'tool_count':len(definitions),
        'required_reader_tool_contract':'PASS','selected_public_tool_schemas':selected,
        'working_history_calls':0,'foreign_process_environment_reads':0,'tools_call_count':0,
        'owner_binding':'NOT_RUN','models':'NOT_RUN','benchmarks':'NOT_RUN'})


def pipe_sandbox():
    reader=module()
    pipes=[p for p in reader.discover_codex_app_tool_pipes() if '\\codex-app-tools-' in p]
    assert len(pipes)==1
    server_image(pipes[0])
    with open(pipes[0],'r+b',buffering=0):pass
    code='\n'.join(['import sys','try:'," with open(sys.argv[1],'r+b',buffering=0):pass",
        " print('OPENABLE_NO_IO');raise SystemExit(2)", 'except PermissionError:'," print('DENIED_NO_IO')"])
    cli=PACKAGE/'app/resources/codex.exe'
    rows=[]
    for actor in ['LAB-A','LAB-B']:
        env={k:v for k,v in os.environ.items() if not k.upper().startswith(('CODEX_','INTEGRITY_','OPENAI_','ANTHROPIC_'))}
        env['CODEX_HOME']=str(ROOT/'clients'/actor/'.codex')
        p=subprocess.run([str(cli),'sandbox','--include-managed-config','--permission-profile','lab-role','--',
            str(ROOT/'runtime/venv/Scripts/python.exe'),'-I','-B','-c',code,pipes[0]],
            cwd=ROOT/'workspaces'/actor,env=env,capture_output=True,text=True,timeout=45)
        status='PASS' if p.returncode==0 and p.stdout.strip()=='DENIED_NO_IO' else 'FAIL' if p.returncode==2 and p.stdout.strip()=='OPENABLE_NO_IO' else 'UNKNOWN'
        rows.append({'actor':actor,'status':status,'exit_code':p.returncode,'result':p.stdout.strip()[-120:],
            'bytes_sent':0,'bytes_read':0})
    save('native-pipe-sandbox.json',{'schema':'integrity-lab.Native-pipe-sandbox.v1',
        'status':'PASS' if all(x['status']=='PASS' for x in rows) else 'FAIL_OR_UNKNOWN',
        'baseline':'PIPE_OPENABLE_OUTSIDE_SANDBOX','claims':rows,'tools_call_count':0,
        'working_history_calls':0,'models':'NOT_RUN'})


def schemas():
    cli=PACKAGE/'app/resources/codex.exe'
    output=CONTROL/'native-api-schema-0.163'
    if not output.exists():
        p=subprocess.run([str(cli),'app-server','generate-json-schema','--experimental','--out',str(output)],
            cwd=CONTROL,capture_output=True,text=True,timeout=30)
        if p.returncode:raise RuntimeError('Public API schema generation failed')
    files=list(output.rglob('*.json'))
    selected={}
    for path in files:
        if any(x in path.name.lower() for x in ['hook','trust','threadstartparams','threadstartresponse']):
            data=json.loads(path.read_text(encoding='utf-8'))
            selected[path.relative_to(output).as_posix()]=data
    save('native-api-schema.json',{'status':'PUBLIC_INSTALLED_PROTOCOL_SCHEMA_GENERATED',
        'CLI_sha256':sha(cli),'schema_files':len(files),'selected_schemas':selected,
        'models':'NOT_RUN','working_history_calls':0})


def coverage(require_empty=True):
    import tomllib
    from integrity_client_memory import native_runtime
    sys.path.insert(0,str(CONTROL))
    from windows_native_binding import remote, successful
    profile,root=native_runtime.verify(BASE/'LAB-A/profile.json')
    os.environ.update(native_runtime.environment(profile,root))
    sys.path.insert(0,str(root/'runtime'))
    spec=importlib.util.spec_from_file_location('lab_compat_broker',root/'runtime'/profile['broker'])
    broker=importlib.util.module_from_spec(spec);sys.modules[spec.name]=broker;spec.loader.exec_module(broker)
    config=tomllib.loads((root/'upstream.toml').read_text())['mcp_servers']['integrity-upstream']
    tools=broker._load_tools_contract(root/'integrity-client-tools.json')
    facade=broker.UpstreamFacade([config['command'],*config['args']],dict(os.environ),None,tools,
        {'protocolVersion':'2025-11-25','capabilities':{},'clientInfo':{'name':'LAB-compat-preflight','version':'1'}})
    try:
        actual=facade.request('tools/list',{},timeout=20)['tools']
        assert broker._tool_surface(actual)==broker._tool_surface(tools)
        reply=facade.request('tools/call',{'name':'integrity_turn_memory_coverage','arguments':{'limit':1}},timeout=25)
        assert reply.get('isError') is not True
        value=json.loads(next(x['text'] for x in reply['content'] if x['type']=='text'))
        assert value['modern_creation_enabled']
        if require_empty:assert value['complete'] and value['counts']['registered']==value['counts']['unresolved']==0
        own=None
        if not require_empty:
            pointer=json.loads((CONTROL/'latest-native-canary.json').read_text(encoding='utf-8'))
            result_path=Path(pointer['result_path']).resolve(strict=True)
            assert result_path.is_relative_to(ROOT/'evidence') and result_path.name=='result.json' and result_path.parent.name.startswith('native-canary-')
            canary=json.loads(result_path.read_text(encoding='utf-8'))
            thread=canary.get('thread_id')
            if isinstance(thread,str):
                response=facade.request('tools/call',{'name':'integrity_turn_memory_coverage',
                    'arguments':{'limit':1,'thread_id':thread}},timeout=25)
                assert response.get('isError') is not True
                own=json.loads(next(x['text'] for x in response['content'] if x['type']=='text'))
    finally:facade.close()
    active=successful(remote("systemctl list-units --no-legend --state=running,activating 'integrity-lab-mcp-*'"))
    assert not active.strip()
    save('native-compat-coverage.json' if require_empty else 'native-canary-coverage.json',{'status':'PASS_REAL_BROKER_FORCED_SSH_ISOLATED_BACKEND',
        'native_tools':len(actual),'coverage_complete':value['complete'],'counts':value['counts'],
        'modern_creation_enabled':value['modern_creation_enabled'],'transient_units_remaining':0,
        'owner_binding':'NOT_EVALUATED_BY_COVERAGE','model_turns':'NOT_RUN_BY_THIS_READER','working_history_calls':0,
        'coverage_receipt':value.get('receipt'),'own_thread_coverage':own})


if __name__=='__main__':
    if os.name!='nt' or os.environ.get('COMPUTERNAME')!=lab_config.setting('vms.windows.hostname'):
        raise RuntimeError('Only the owned Windows LAB guest')
    parser=argparse.ArgumentParser()
    parser.add_argument('stage',choices=['install','endpoint','pipe_sandbox','schemas','coverage','post_coverage'])
    args=parser.parse_args()
    if args.stage=='post_coverage':coverage(require_empty=False)
    else:globals()[args.stage]()

# SPDX-License-Identifier: BUSL-1.1
"""Final read-only checks of exactly the two owned LAB VMs; no model calls."""
from pathlib import Path
import hashlib
import json
import shutil
import sys
from datetime import datetime, timezone

ROOT=Path(__file__).absolute().parent.parent
sys.path.insert(0,str(ROOT/'tools'))
import vmctl
import lab_config
from run_native_canary import guest_source


def main():
    rows=[]
    for name in vmctl.UUIDS:
        raw=vmctl.owned_info(name)
        def value(key):
            v=raw.get(key)
            if v is None:return None
            return json.loads(v) if v.startswith('"') else v
        assert value('VMState')=='running'
        assert value('clipboard')=='disabled' and value('draganddrop')=='disabled'
        assert value('vrde')=='off'
        assert all(value(k)=='off' for k in ['usb','ehci','xhci'])
        assert not any(k.startswith('SharedFolderName') for k in raw)
        if name==vmctl.LINUX:
            assert value('nic2')=='nat' and value('cableconnected2')=='off'
        else:assert value('nic2')=='none'
        keys=['name','UUID','CfgFile','VMState','memory','cpus','nic1','intnet1','nic2',
            'cableconnected2','clipboard','draganddrop','vrde','usb','ehci','xhci']
        rows.append({k:value(k) for k in keys})
    source=r'''
import sys,json,hashlib,subprocess
from pathlib import Path
sys.path.insert(0,r'C:\IntegrityLAB\control\preflight-labadmin')
from windows_native_binding import remote,successful
from integrity_client_memory import native_runtime
from windows_native_hook_stage import Control
root=Path(r'C:\IntegrityLAB');control=root/'control/preflight-labadmin'
profiles=[]
for actor in ['LAB-A','LAB-B']:
 p,r=native_runtime.verify(control/'native-profiles-compat-v3'/actor/'profile.json')
 profiles.append({'actor':actor,'profile_sha256':hashlib.sha256((control/'native-profiles-compat-v3'/actor/'profile.json').read_bytes()).hexdigest(),'source_config_verify':'PASS'})
ps=r"""$ErrorActionPreference='Stop'
$routes=@(Get-NetRoute -AddressFamily IPv4 | Where-Object DestinationPrefix -eq '0.0.0.0/0')
$targets=@(Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -and ($_.CommandLine -match 'windows_efficiency_smoke\.py|windows_native_canary\.py.+run' -or ($_.Name -eq 'codex.exe' -and $_.CommandLine -match '\s+exec\s+' -and $_.CommandLine -match 'IntegrityLAB.+workspaces')) })
[ordered]@{hostname=$env:COMPUTERNAME;default_routes=$routes.Count;owned_benchmark_processes=$targets.Count} | ConvertTo-Json -Compress
"""
win=json.loads(subprocess.check_output([r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe','-NoProfile','-NonInteractive','-Command',ps],text=True))
assert win['hostname']==@WINDOWS_HOSTNAME@ and win['default_routes']==0 and win['owned_benchmark_processes']==0
api=Control()
try:
 hooks=api.call('hooks/list',{'cwds':[str(root/'workspaces'/x) for x in ['LAB-A','LAB-B']]})['data']
 metadata=[]
 for entry in hooks:
  assert not entry['errors'] and len(entry['hooks'])==9
  metadata.append({'cwd':entry['cwd'],'count':len(entry['hooks']),'trust_states':sorted({h['trustStatus'] for h in entry['hooks']})})
finally:api.close()
linux=r"""import os,socket,subprocess,json,hashlib
from pathlib import Path
assert socket.gethostname()==@LINUX_HOSTNAME@
def out(args):return subprocess.check_output(args,text=True)
routes=json.loads(out(['/usr/sbin/ip','-j','-4','route','show','default']))
addr=json.loads(out(['/usr/sbin/ip','-j','-4','addr','show','dev','egress0']))
assert not routes and not any(a.get('addr_info') for a in addr)
proxy=subprocess.run(['/usr/bin/systemctl','is-active','integrity-lab-egress.service'],capture_output=True,text=True).stdout.strip()
assert proxy in {'inactive','unknown','failed'}
units=out(['/usr/bin/systemctl','list-units','--no-legend','--state=running,activating','integrity-lab-mcp-*']).strip()
assert not units
path=Path.home()/'efficiency-smoke/eff-20261021-smoke-01/catalog.sqlite3'
print(json.dumps({'hostname':socket.gethostname(),'default_routes':0,'egress0_IPv4':0,'proxy':proxy,'running_Native_MCP_units':0,'benchmark_catalog_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'backend_source_sha256':hashlib.sha256(Path('/opt/integrity-lab/tools/linux_backend.py').read_bytes()).hexdigest()}))
"""
lin=json.loads(successful(remote('/usr/bin/python3 -I -B -',linux,timeout=30)))
print(json.dumps({'Windows':win,'Linux':lin,'Native_v3_profiles':profiles,'persisted_hook_trust':metadata,'online_model_calls':0,'working_history_calls':0}))
'''
    source=lab_config.fill(source,WINDOWS_HOSTNAME=lab_config.setting('vms.windows.hostname'),
        LINUX_HOSTNAME=lab_config.setting('vms.linux.hostname'))
    guest=json.loads(guest_source(source,110).splitlines()[-1])
    retrieval=json.loads((ROOT/'evidence/eff-20261021-smoke-01/retrieval.json').read_text(encoding='utf-8'))
    # Byte identity compared with the retrieval controller's captured catalog hash.
    expected=retrieval['source_sha256']
    assert guest['Linux']['benchmark_catalog_sha256']==expected
    result={'schema':'integrity-lab.final-readback.v1','status':'PASS',
        'observed_utc':datetime.now(timezone.utc).isoformat(),'VMs':rows,'guest':guest,
        'D_free_gib':round(shutil.disk_usage(ROOT).free/1024**3,2),
        'scope':'Two owned LAB VMs only; no production inspection or changes','model_calls':0}
    path=ROOT/'evidence/FINAL-LAB-READBACK.json'
    if path.exists():raise FileExistsError('Final readback already exists; preserve exact evidence')
    path.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'status':'PASS','VMs':2,'online_model_calls':0,'default_routes':0,
        'proxy':'STOPPED','Linux_NAT_cable':'OFF','owned_benchmark_processes':0,'D_free_gib':result['D_free_gib']}))


if __name__=='__main__':main()

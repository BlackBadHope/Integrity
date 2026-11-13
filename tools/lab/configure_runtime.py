# SPDX-License-Identifier: BUSL-1.1
"""Render isolated homes/profiles. Creates no Codex threads or turns."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).absolute().parent))
from runtime_common import ROOT,BASE_PYTHON,CLI,within
import json
import lab_config

DENIED=[Path(x) for x in lab_config.setting('host.denied_paths')]
if not DENIED:raise LookupError('lab configuration key host.denied_paths must list the working paths the lab profiles deny')

def literal(value):return "'"+str(value)+"'"
base='''approval_policy = "never"
default_permissions = "lab-controller"
web_search = "disabled"
[windows]
sandbox = "mxc"
[features]
prefer_mxc = true
apps = false
plugins = false
memories = false
[agents]
enabled = true
max_concurrent_threads_per_session = 2
[skills]
include_instructions = false
[skills.bundled]
enabled = false
'''
profiles={
 'lab-controller':{ROOT:'write'},
 'lab-shell-a':{ROOT/'runtime/probes/LAB-A':'write',ROOT/'tools/sandbox_probe.py':'read'},
 'lab-shell-b':{ROOT/'runtime/probes/LAB-B':'write',ROOT/'tools/sandbox_probe.py':'read'},
}
reader=ROOT/'runtime/integrity-next-source/examples/local-memory/memory_server.py'
catalogs={'shared':'shared','session-a':'session-a','session-b':'session-b'}
for backend in catalogs:
 for actor in ['LAB-A','LAB-B']:
  profiles['lab-reader-'+backend+'-'+actor.lower()]={ROOT/'state/memory'/catalogs[backend]/'catalog.sqlite3':'read',ROOT/'runtime/mcp-snapshots'/backend/actor:'write',reader:'read'}
for name,paths in profiles.items():
 base+=f'\n[permissions.{name}.filesystem]\n":root" = "deny"\n":minimal" = "read"\n'
 for path,access in {BASE_PYTHON:'read',ROOT/'runtime/venv':'read',**paths}.items():base+=literal(path)+' = "'+access+'"\n'
 base+=''.join(literal(x)+' = "deny"\n' for x in DENIED)
 base+=f'[permissions.{name}.network]\nenabled = false\n'
within('runtime/controller-home/config.toml').write_text(base,encoding='utf-8')
for actor,profile in [('LAB-A','lab-shell-a'),('LAB-B','lab-shell-b')]:
 actor_config=base.replace('default_permissions = "lab-controller"','default_permissions = "'+profile+'"')
 # Supported four-tool reader is named honestly; it is NOT a Native lifecycle facade.
 args=['-I','-B',str(ROOT/'tools/readonly_mcp_host.py'),'--backend','shared','--actor',actor]
 actor_config+='\n[mcp_servers.integrity_lab_reader]\nrequired = true\ncommand = '+literal(ROOT/'runtime/venv/Scripts/python.exe')+'\nargs = '+json.dumps(args)+'\nstartup_timeout_sec = 45\ntool_timeout_sec = 45\n'
 # Only explicit environment names needed by the native Windows sandbox; no auth/provider/bus secrets.
 actor_config+='env_vars = ["SystemRoot", "SystemDrive", "WINDIR", "COMSPEC", "PATH", "USERPROFILE", "LOCALAPPDATA", "APPDATA", "TEMP", "TMP"]\n'
 actor_config+='[mcp_servers.integrity_lab_reader.env]\nCODEX_HOME = '+literal(ROOT/'runtime/controller-home')+'\nPYTHONDONTWRITEBYTECODE = "1"\n'
 within('runtime/codex-homes/'+actor+'/config.toml').write_text(actor_config,encoding='utf-8')
print(json.dumps({'rendered_homes':3,'permission_profiles':len(profiles),'MCP_required':True,'agents_started':0,'benchmarks_started':0}))

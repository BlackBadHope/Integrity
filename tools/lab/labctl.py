# SPDX-License-Identifier: BUSL-1.1
"""Offline inspection only. Deliberately has no run/send/serve command."""
from pathlib import Path
import sys
sys.dont_write_bytecode = True
sys.path.insert(0,str(Path(__file__).absolute().parent))
from guard import checked, install
install()
import argparse
import json

parser=argparse.ArgumentParser(description="IntegrityLAB: status/plan only; launching agents is not implemented")
parser.add_argument("command",choices=["status","plan"])
args=parser.parse_args()
if args.command=="status":
    p=checked("state/PREPARED.json")
    data=json.loads(p.read_text(encoding="utf-8")) if p.exists() else {"phase":"NOT_PREPARED"}
    data.pop("markers",None)
    config=json.loads(checked('lab.json').read_text(encoding='utf-8'))
    data['phase']=config['phase']
    data['pilot_execution_allowed']=config.get('pilot_execution_allowed',False)
    data['native_lifecycle']=config['adapters']['integrity_mcp'].get('native_lifecycle','NOT_CONFIGURED')
    data['managed_hooks_isolation']=config.get('managed_hooks_isolation','NOT_RUN')
    data['VM_preparation']=config.get('virtualization',{'stage':'NOT_CONFIGURED'})
    print(json.dumps(data,ensure_ascii=False,indent=2))
else:
    data=json.loads(checked("controller/pilot-plan.json").read_text(encoding="utf-8"))
    print(json.dumps({k:v for k,v in data.items() if k!="episodes"},ensure_ascii=False,indent=2))

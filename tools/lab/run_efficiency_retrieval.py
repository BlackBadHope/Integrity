# SPDX-License-Identifier: BUSL-1.1
"""Controller-only four-query retrieval against a fresh Linux LAB catalog."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).absolute().parent))
import base64
import hashlib
import json
from windows_guest_control import ROOT,run
from windows_vm_stage import require
import lab_config

RUN_ID='eff-20261021-smoke-01'

def main():
    fixture=ROOT/'controller/efficiency-smoke-fixtures.json'
    spec=json.loads(fixture.read_text(encoding='utf-8'))
    payload={'run_id':RUN_ID,'expected_hostname':lab_config.setting('vms.linux.hostname'),'cases':[{k:c[k] for k in ['id','task_id','corpus','query']} for c in spec['cases']]}
    source=(ROOT/'tools/linux_efficiency_recall.py').read_bytes()
    script='import io,sys,base64\nsys.stdin=io.StringIO(base64.b64decode('+repr(base64.b64encode(json.dumps(payload).encode()).decode())+').decode())\nexec(compile(base64.b64decode('+repr(base64.b64encode(source).decode())+'),"<LAB-efficiency-recall>","exec"))'
    guest="import sys,json\nsys.path.insert(0,r'C:\\IntegrityLAB\\control\\preflight-labadmin')\nfrom windows_native_binding import remote,successful\nprint(successful(remote('/opt/integrity-lab/venv/bin/python -I -B -',"+repr(script)+",timeout=75)))"
    output=ROOT/'evidence'/RUN_ID
    output.mkdir(exist_ok=True)
    target=output/'retrieval.json'
    assert not target.exists(),'Retain the existing exact retrieval evidence; do not repeat this run'
    result=json.loads(require(run(r'C:\IntegrityLAB\runtime\venv\Scripts\python.exe',['-I','-B','-c',guest],90)))
    result['fixture_sha256']=hashlib.sha256(fixture.read_bytes()).hexdigest()
    target.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'status':'RETRIEVAL_COMPLETE','run_id':RUN_ID,'cases':[{k:c[k] for k in ['id','retrieval_seconds']} for c in result['cases']],
        'evidence':str(target),'catalog_unchanged':result['source_catalog_unchanged']}))

if __name__=='__main__':main()

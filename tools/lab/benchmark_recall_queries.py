# SPDX-License-Identifier: BUSL-1.1
"""Read-only query A/B on the unchanged synthetic catalog, without models."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).absolute().parent))
import json
from windows_guest_control import ROOT,run
from windows_vm_stage import require
import lab_config

def main():
    fixture=json.loads((ROOT/'controller/efficiency-smoke-fixtures.json').read_text(encoding='utf-8'))
    cases=[{k:c[k] for k in ['id','task_id']} for c in fixture['cases']]
    source='''from pathlib import Path
import json,hashlib,time,os,socket
assert os.geteuid()==1000 and socket.gethostname()==@LINUX_HOSTNAME@
from integrity_guardian.memory_synapse_lts import MemorySynapseLtsService
from integrity_guardian.memory_synapse_mcp import MemorySynapseMcp
path=Path.home()/'efficiency-smoke/eff-20261021-smoke-01/catalog.sqlite3'
before=hashlib.sha256(path.read_bytes()).hexdigest();rows=[]
for case in CASES:
 for variant,query in [('Q1-exact-task-id',case['task_id']),('Q2-quoted-task-id','"'+case['task_id']+'"')]:
  started=time.perf_counter();server=MemorySynapseMcp(MemorySynapseLtsService(path,immutable_catalog=True),audit=lambda _:None)
  try:
   server.call('integrity_memory_capabilities',{});snapshot=server.call('integrity_seed_snapshot',{})
   recall=server.call('integrity_seed_recall',{'snapshot_id':snapshot['snapshot_id'],'query':query,'limit':8,'include_legacy':False})
   rows.append({'id':case['id'],'variant':variant,'query':query,'recall':recall,'retrieval_seconds':round(time.perf_counter()-started,6)})
  finally:server.close()
assert hashlib.sha256(path.read_bytes()).hexdigest()==before
print(json.dumps({'rows':rows,'catalog_sha256':before,'catalog_unchanged':True,'model_calls':0}))
'''.replace('CASES',repr(cases))
    source=lab_config.fill(source,LINUX_HOSTNAME=lab_config.setting('vms.linux.hostname'))
    guest="import sys\nsys.path.insert(0,r'C:\\IntegrityLAB\\control\\preflight-labadmin')\nfrom windows_native_binding import remote,successful\nprint(successful(remote('/opt/integrity-lab/venv/bin/python -I -B -',"+repr(source)+",timeout=55)))"
    value=json.loads(require(run(r'C:\IntegrityLAB\runtime\venv\Scripts\python.exe',['-I','-B','-c',guest],70)))
    prior=json.loads((ROOT/'evidence/eff-20261021-smoke-01/retrieval.json').read_text(encoding='utf-8'))
    allrows=[{'id':c['id'],'variant':'Q0-broad','query':c['query'],'recall':c['recall'],'retrieval_seconds':c['retrieval_seconds']} for c in prior['cases']]+value['rows']
    truth={c['id']:set(c['required_sources']) for c in fixture['cases']}
    for r in allrows:
        keys={json.loads(e['summary'])['key'] for e in r['recall']['events']}
        r['required_source_recall']=len(keys&truth[r['id']])/len(truth[r['id']])
        r['returned_source_keys']=sorted(keys)
    value.update(schema='integrity-lab.recall-query-ab.v1',rows=allrows,
        Q1_selection='Predeclared primary optimization: query only the known synthetic task_id; Q2 is a diagnostic ablation',
        Q0_reused=True)
    target=ROOT/'evidence/eff-20261021-smoke-01/query-ab.json'
    assert not target.exists()
    target.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps([{'id':r['id'],'variant':r['variant'],'source_recall':r['required_source_recall'],'seconds':r['retrieval_seconds']} for r in allrows]))

if __name__=='__main__':main()

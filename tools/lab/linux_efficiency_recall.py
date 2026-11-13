# SPDX-License-Identifier: BUSL-1.1
"""Synthetic read-only Integrity retrieval for the separate efficiency smoke.

No Native identity, lifecycle, append, network service or existing backend edit.
The controller supplies fixture documents, not a model-supplied database path.
"""
from pathlib import Path
import hashlib
import json
import os
import re
import socket
import sys
import time


def main():
    # Sent from the host without the lab configuration; the controller supplies the guest name.
    data=json.load(sys.stdin)
    assert sys.platform=='linux' and os.geteuid()==1000 and socket.gethostname()==data['expected_hostname']
    os.umask(0o077)
    run=data['run_id'];assert re.fullmatch(r'eff-[a-z0-9-]{1,48}',run)
    root=Path.home()/'efficiency-smoke'/run
    root.mkdir(parents=True,mode=0o700,exist_ok=False)
    from integrity_guardian.seed_catalog import SeedCatalog
    from integrity_guardian.memory_synapse_lts import MemorySynapseLtsService
    from integrity_guardian.memory_synapse_mcp import MemorySynapseMcp
    catalog_path=root/'catalog.sqlite3'
    events=[]
    for case in data['cases']:
        for row in case['corpus']:
            i=len(events)+1
            events.append({'id':i,'event_uid':run+':'+row['key'],'ts_utc':'2026-10-21T00:00:00Z',
                'actor':'LAB-fixture-controller','action':'seed_doctrine_declared','level':'info',
                'summary':json.dumps(row,ensure_ascii=False,sort_keys=True),'details':{'synthetic':True,'fixture':row},
                'tags':['LAB','synthetic',case['task_id']]})
    SeedCatalog(catalog_path).import_events(events,source_namespace='seed://project/'+run,source_identity='lab-only:'+run)
    before=hashlib.sha256(catalog_path.read_bytes()).hexdigest()
    result={'schema':'integrity-lab.efficiency-retrieval.v1','run_id':run,
        'source_plane':'CONTROLLER_DELIVERED_REAL_INTEGRITY_READONLY_SNAPSHOT_RECALL',
        'native_end_to_end':False,'catalog_path':str(catalog_path),'source_events':len(events),'cases':[]}
    for case in data['cases']:
        # Fresh immutable read session for every pair; the complete identical
        # fixture catalog is available to each query, with no oracle filtering.
        started=time.perf_counter()
        server=MemorySynapseMcp(MemorySynapseLtsService(catalog_path,immutable_catalog=True),audit=lambda _:None)
        try:
            capabilities=server.call('integrity_memory_capabilities',{})
            snapshot=server.call('integrity_seed_snapshot',{})
            recall=server.call('integrity_seed_recall',{'snapshot_id':snapshot['snapshot_id'],
                'query':case['query'],'limit':8,'include_legacy':False})
            result['cases'].append({'id':case['id'],'query':case['query'],'snapshot':snapshot,
                'recall':recall,'retrieval_seconds':round(time.perf_counter()-started,6)})
        finally:server.close()
    assert hashlib.sha256(catalog_path.read_bytes()).hexdigest()==before
    result['source_catalog_unchanged']=True;result['source_sha256']=before
    result['native_preflight_backend_changed']=False;result['model_requests']=0
    (root/'retrieval.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(result,ensure_ascii=False))


if __name__=='__main__':main()
